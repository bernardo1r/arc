package arc

import (
	"bytes"
	"database/sql"
	_ "embed"
	"errors"
	"io"
	"os"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	queryInsertMetadata = `INSERT INTO metadata(
		name,
		size,
		blocks,
		mod_time,
		compressed,
		encrypted
	) VALUES (?, ?, ?, ?, ?, ?)`

	queryGetFileId = `SELECT id FROM metadata WHERE name = ?`

	queryInsertData = `INSERT INTO data VALUES (?, ?, ?)`

	queryUpdateMetadata = `UPDATE metadata SET size = ?, blocks = ? WHERE id = ?`
)

// DefaultBlocksize is the default size, in bytes, of a file chunk
// within the container.
const DefaultBlocksize = 8 * (1 << 10) // 8 KiB

//go:embed ddl.sql
var queryDDL []byte

// ErrWriterClosed is returned when Writer is used after closed.
var ErrWriterClosed = errors.New("writer closed")

// Header represents a file in the arc file.
type Header struct {
	// Name of the file.
	Name string

	// ModTime is the last time the file was modified,
	// in UTC location.
	ModTime time.Time

	// Compression indicates what level of compression
	// is applied to the file.
	//
	// The default value (0) indicates that no compression
	// is applied.
	//
	// When reading the file this field must only be checked
	// against the zero value (0).
	Compression zstd.EncoderLevel

	// Encryption indicates if file is encrypted.
	Encryption bool

	// Transaction indicates if all the blocks of the file
	// will be written in a single transaction.
	Transaction bool
}

func (header *Header) check() error {
	if header.Name == "" {
		return errors.New("file name cannot be empty")
	}
	var defaultVal time.Time
	if header.ModTime == defaultVal {
		header.ModTime = time.Now().UTC()
	}
	return nil
}

// Writer implements a arc container writer. [Writer.WriteHeader] initiates
// a new file with the providaded [Header], and then Writer can be used as an
// io.Writer.
type Writer struct {
	writer                io.WriteCloser
	bytesRead             int
	blocksize             int
	db                    *sql.DB
	currDataWriter        *dataWriter
	currCompressionWriter *zstd.Encoder
	err                   error
}

func prepareDB(databasePath string, databaseArgs string) (*sql.DB, error) {
	err := os.Remove(databasePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	db, err := sql.Open("sqlite3", "file:"+databasePath+"?"+databaseArgs)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(string(queryDDL))
	return db, err
}

// NewWriter creates a new Writer and a container file with name databasePath.
func NewWriter(databasePath string, databaseArgs string, blocksize int) (*Writer, error) {
	writer := new(Writer)
	writer.blocksize = blocksize
	writer.db, writer.err = prepareDB(databasePath, databaseArgs)
	return writer, writer.err
}

func (writer *Writer) flush() error {
	if writer.currDataWriter == nil {
		return nil
	}

	if writer.currCompressionWriter != nil {
		writer.err = writer.currCompressionWriter.Close()
		if writer.err != nil {
			return writer.err
		}
	}
	writer.err = writer.currDataWriter.Close()
	if writer.err != nil {
		return writer.err
	}

	_, writer.err = writer.db.Exec(
		queryUpdateMetadata,
		writer.bytesRead,
		writer.currDataWriter.currBlock,
		writer.currDataWriter.id,
	)
	return writer.err
}

// WriteHeader prepares the Writer for writing the file described by header.
func (writer *Writer) WriteHeader(header *Header) error {
	if writer.err != nil {
		return writer.err
	}

	writer.err = header.check()
	if writer.err != nil {
		return writer.err
	}
	if writer.flush() != nil {
		return writer.err
	}

	_, writer.err = writer.db.Exec(
		queryInsertMetadata,
		header.Name,
		0,
		0,
		header.ModTime.Unix(),
		header.Compression != 0,
		header.Encryption,
	)
	if writer.err != nil {
		return writer.err
	}

	var id int
	writer.err = writer.db.QueryRow(queryGetFileId, header.Name).Scan(&id)
	if writer.err != nil {
		return writer.err
	}

	writer.currDataWriter, writer.err = newDataWriter(writer.db, id, writer.blocksize, header.Transaction)
	if writer.err != nil {
		return writer.err
	}

	if header.Compression != 0 {
		writer.currCompressionWriter, writer.err = zstd.NewWriter(
			writer.currDataWriter,
			zstd.WithEncoderLevel(header.Compression),
		)
		writer.writer = writer.currCompressionWriter
	} else {
		writer.writer = writer.currDataWriter
		writer.currCompressionWriter = nil
	}

	return writer.err
}

// WriteFile looks for a filepath file and add to container accordingly to header.
// The file is added all in one transaction.
func (writer *Writer) WriteFile(header *Header, filepath string) (err error) {
	if writer.err != nil {
		return writer.err
	}

	header.Transaction = true
	if writer.WriteHeader(header) != nil {
		return writer.err
	}

	var file *os.File
	file, writer.err = os.Open(filepath)
	if writer.err != nil {
		return writer.err
	}
	defer func() {
		err2 := file.Close()
		if err2 != nil && err == nil {
			writer.err = err2
			err = writer.err
		}
	}()

	var read int64
	read, writer.err = io.Copy(writer.writer, file)
	writer.bytesRead = int(read)
	if writer.err != nil {
		return writer.err
	}

	writer.err = writer.flush()
	writer.currDataWriter = nil
	return writer.err
}

// Write writes the current file in the container, implementing
// the io.Writer interface.
func (writer *Writer) Write(p []byte) (int, error) {
	if writer.err != nil {
		return 0, writer.err
	}

	var read int
	read, writer.err = writer.writer.Write(p)
	writer.bytesRead += read
	return read, writer.err
}

// Close closes the container and flushes any remaining data of
// the current file to the container.
// Subsequently calls to Close or any other method will yield [ErrWriterClosed]
func (writer *Writer) Close() error {
	if writer.err != nil {
		return writer.err
	}

	writer.err = writer.flush()
	if writer.err != nil {
		return writer.err
	}

	writer.err = writer.db.Close()
	if writer.err != nil {
		return writer.err
	}

	writer.err = ErrWriterClosed
	return nil
}

type dataWriter struct {
	transaction *sql.Tx
	statement   *sql.Stmt
	id          int
	currBlock   int
	blockSize   int
	buffer      bytes.Buffer
	err         error
}

func newDataWriter(db *sql.DB, id int, blocksize int, transaction bool) (*dataWriter, error) {
	dwriter := &dataWriter{
		id:        id,
		blockSize: blocksize,
	}

	var err error
	if transaction {
		dwriter.transaction, err = db.Begin()
		if err != nil {
			return nil, err
		}
		dwriter.statement, err = dwriter.transaction.Prepare(queryInsertData)
		if err != nil {
			return nil, err
		}
	} else {
		dwriter.statement, err = db.Prepare(queryInsertData)
		if err != nil {
			return nil, err
		}
	}

	dwriter.buffer.Grow(dwriter.blockSize)
	return dwriter, nil
}

func (dwriter *dataWriter) cleanup() {
	dwriter.statement.Close()
	if dwriter.transaction != nil {
		dwriter.transaction.Rollback()
	}
}

func (dwriter *dataWriter) Write(p []byte) (n int, err error) {
	if dwriter.err != nil {
		return 0, dwriter.err
	}
	defer func() {
		if err != nil {
			dwriter.cleanup()
		}
	}()

	total := len(p)
	for len(p) > 0 {
		size := min(dwriter.blockSize-dwriter.buffer.Len(), len(p))
		written, err := dwriter.buffer.Write(p[:size])
		if err != nil {
			dwriter.err = err
			return written, err
		}

		if dwriter.buffer.Len() == dwriter.blockSize {
			dwriter.err = dwriter.Flush()
			if dwriter.err != nil {
				return total, dwriter.err
			}
		}

		p = p[size:]
	}

	return total, nil
}

func (dwriter *dataWriter) Flush() (err error) {
	if dwriter.err != nil {
		return dwriter.err
	}
	defer func() {
		if err != nil {
			dwriter.cleanup()
		}
	}()

	_, dwriter.err = dwriter.statement.Exec(dwriter.id, dwriter.currBlock, dwriter.buffer.Bytes())
	if dwriter.err != nil {
		return dwriter.err
	}
	dwriter.buffer.Reset()

	dwriter.currBlock++
	return nil
}

func (dwriter *dataWriter) Close() (err error) {
	if dwriter.err != nil {
		return dwriter.err
	}
	defer func() {
		if err != nil {
			dwriter.cleanup()
		}
	}()

	if dwriter.Flush() != nil {
		return dwriter.err
	}

	if dwriter.transaction != nil {
		dwriter.err = dwriter.statement.Close()
		if dwriter.err != nil {
			return dwriter.err
		}
		dwriter.err = dwriter.transaction.Commit()
	} else {
		dwriter.err = dwriter.statement.Close()
	}
	if dwriter.err != nil {
		return dwriter.err
	}

	dwriter.err = ErrWriterClosed
	return nil
}

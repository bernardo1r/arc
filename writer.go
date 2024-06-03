package arc

import (
	"bytes"
	"database/sql"
	_ "embed"
	"errors"
	"io"
	"os"
	"time"

	"github.com/bernardo1r/encdec"
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

	queryInsertEncryptedMetadata = `INSERT INTO encryption_metadata VALUES (?, ?)`

	queryInsertData = `INSERT INTO data VALUES (?, ?, ?)`

	queryInsertEncryptionKeyParams = `INSERT INTO encryption_key_params VALUES (?)`

	queryIdByName = `SELECT id FROM metadata WHERE name = ?`

	queryUpdateFileSize = `UPDATE metadata SET size = ?, blocks = ? WHERE id = ?`

	queryUpdateFilename = `UPDATE metadata SET name = ? WHERE id = ?`
)

// DefaultBlocksize is the default size, in bytes, of a file chunk
// within the container.
const DefaultBlocksize = 8 * (1 << 10) // 8 KiB

const encryptionKeysize = 32

//go:embed ddl.sql
var queryDDL []byte

const databaseArgs = "?_foreign_keys=on"

var (
	// ErrWriterClosed is returned when Writer is used after closed.
	ErrWriterClosed = errors.New("writer closed")

	// ErrEmptyPassword is returned when a file have encryption enabled, but
	// no password was provided.
	ErrEmptyPassword = errors.New("encrypted marked file with no password provided")

	// ErrNotEncrypted is returned when a file isn't marked for encryption, but
	// a password was provided.
	ErrNotEncrypted = errors.New("provided password from unencrypted container")

	// ErrNoFilename is returned when is tried to create a file with no name.
	ErrNoFilename = errors.New("attempt to create file with no name")

	// ErrnoFileSelected is returned when reading a [Reader] with no file
	// selected previously.
	ErrNoFileSelected = errors.New("no file selected for reading")

	// ErrWrongPassword is returned when providing the wrong password to an
	// container with encrypted files.
	ErrWrongPassword = errors.New("wrong password provided")

	ErrPadding = errors.New("corrupted filename pad")
)

// Header represents a file in the arc file.
type Header struct {
	// Id of the file in the container.
	//
	// The Id is only relevent for the [Reader],
	// and thereby ignored by the [Writer].
	Id int

	// Name of the file.
	Name string

	// Size, in bytes, of the file, outside the container.
	//
	// As the [Header.Id] field, this field is too ignored
	// by the [Writer].
	Size int

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

	// Encryption indicates if file is encrypted or not.
	Encryption bool
}

func (header *Header) check() error {
	if header.Name == "" {
		return ErrNoFilename
	}
	var defaultVal time.Time
	if header.ModTime == defaultVal {
		header.ModTime = time.Now().UTC()
	}
	return nil
}

// Writer implements a arc container writer. [Writer.WriteHeader] initiates
// a new file with the providaded [Header], and then the Writer can be
// used as an io.Writer.
type Writer struct {
	blocksize      int
	encryptionKey  []byte
	db             *sql.DB
	currWriters    []io.WriteCloser
	currBytesRead  int
	currDataWriter *dataWriter
	err            error
}

func prepareDB(databasePath string) (*sql.DB, error) {
	err := os.Remove(databasePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	db, err := sql.Open("sqlite3", "file:"+databasePath+databaseArgs)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(string(queryDDL))
	return db, err
}

func (writer *Writer) createEncryptionKey(password []byte) error {
	var params encdec.Params
	writer.encryptionKey, writer.err = encdec.Key(password, &params)
	if writer.err != nil {
		return writer.err
	}

	var paramsString []byte
	paramsString, writer.err = params.MarshalHeader()
	if writer.err != nil {
		return writer.err
	}
	_, writer.err = writer.db.Exec(queryInsertEncryptionKeyParams, paramsString)
	return writer.err
}

// NewWriter creates a new Writer and a container file with name databasePath.
func NewWriter(databasePath string, blocksize int, password []byte) (*Writer, error) {
	writer := new(Writer)
	writer.blocksize = blocksize
	writer.db, writer.err = prepareDB(databasePath)
	if writer.err != nil {
		return nil, writer.err
	}

	if password != nil {
		err := writer.createEncryptionKey(password)
		if err != nil {
			return nil, err
		}
	}

	return writer, nil
}

func (writer *Writer) flush() error {
	if writer.currWriters == nil {
		return nil
	}

	for i := len(writer.currWriters) - 1; i >= 0; i-- {
		writer.err = writer.currWriters[i].Close()
		if writer.err != nil {
			return writer.err
		}
	}

	_, writer.err = writer.db.Exec(
		queryUpdateFileSize,
		writer.currBytesRead,
		writer.currDataWriter.currBlock,
		writer.currDataWriter.id,
	)

	writer.currWriters = nil
	writer.currDataWriter = nil
	return writer.err
}

func (writer *Writer) prepareFileEncryption(header *Header) (fileDataKey []byte, err error) {
	if writer.encryptionKey == nil {
		return nil, ErrEmptyPassword
	}

	var encryptedKey, fileMasterKey []byte
	encryptedKey, fileMasterKey, writer.err = generateFileMasterKey(writer.encryptionKey, header.Id)
	_, writer.err = writer.db.Exec(queryInsertEncryptedMetadata, header.Id, encryptedKey)
	if writer.err != nil {
		return nil, writer.err
	}

	var filenameKey []byte
	filenameKey, fileDataKey = stretchKey(fileMasterKey)
	var encryptedFilename string
	encryptedFilename, writer.err = encryptFilename(header.Name, filenameKey)
	if writer.err != nil {
		return nil, writer.err
	}
	_, writer.err = writer.db.Exec(queryUpdateFilename, encryptedFilename, header.Id)

	return fileDataKey, writer.err
}

// WriteHeader prepares the Writer for writing the file described by header.
func (writer *Writer) WriteHeader(header *Header, transaction bool) error {
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
	writer.err = writer.db.QueryRow(queryIdByName, header.Name).Scan(&id)
	if writer.err != nil {
		return writer.err
	}
	header.Id = id

	var dataWriter *dataWriter
	dataWriter, writer.err = newDataWriter(writer.db, id, writer.blocksize, transaction)
	if writer.err != nil {
		return writer.err
	}
	writer.currWriters = append(writer.currWriters, dataWriter)
	currWriterId := 0
	writer.currDataWriter = dataWriter

	var currWriter io.WriteCloser
	if header.Encryption {
		key, err := writer.prepareFileEncryption(header)
		if err != nil {
			return err
		}

		var params encdec.Params
		currWriter, writer.err = encdec.NewWriter(key, writer.currWriters[currWriterId], &params)
		if writer.err != nil {
			return writer.err
		}
		writer.currWriters = append(writer.currWriters, currWriter)
		currWriterId++
	}

	if header.Compression != 0 {
		currWriter, writer.err = zstd.NewWriter(
			writer.currWriters[currWriterId],
			zstd.WithEncoderLevel(header.Compression),
		)
		if writer.err != nil {
			return writer.err
		}
		writer.currWriters = append(writer.currWriters, currWriter)
		currWriterId++
	}

	return writer.err
}

// WriteFile looks for a filepath file and add to container accordingly to header.
// The file is added all in one transaction.
func (writer *Writer) WriteFile(header *Header, filepath string) (err error) {
	if writer.err != nil {
		return writer.err
	}

	if writer.WriteHeader(header, true) != nil {
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
	read, writer.err = io.Copy(writer.currWriters[len(writer.currWriters)-1], file)
	writer.currBytesRead = int(read)
	if writer.err != nil {
		return writer.err
	}

	return writer.flush()
}

// Write writes the current file in the container, implementing
// the io.Writer interface.
func (writer *Writer) Write(p []byte) (int, error) {
	if writer.err != nil {
		return 0, writer.err
	}

	var read int
	read, writer.err = writer.currWriters[len(writer.currWriters)-1].Write(p)
	writer.currBytesRead += read
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

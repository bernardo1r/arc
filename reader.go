package arc

import (
	"bytes"
	"database/sql"
	"errors"
	"io"
	"os"
	"time"

	"github.com/bernardo1r/encdec"
	"github.com/klauspost/compress/zstd"
)

const (
	queryMetadata = `SELECT id, name, size, mod_time, compressed, encrypted FROM metadata`

	queryMetadataOptionById = `SELECT compressed, encrypted FROM metadata WHERE id = ?`

	queryEncryptionKeyParams = `SELECT params FROM encryption_key_params`

	queryFileEncryptionKeyIdAny = `SELECT id FROM encryption_metadata LIMIT 1`

	queryFileEncryptionKeyById = `SELECT key FROM encryption_metadata WHERE id = ?`

	queryDataById = `SELECT data.data FROM data WHERE id = ? ORDER BY block_id ASC`
)

type Reader struct {
	currReader    io.Reader
	encryptionKey []byte
	db            *sql.DB
	encrypted     bool
	err           error
}

func (reader *Reader) readEncryptionKey(password []byte) error {
	var paramsString []byte
	reader.err = reader.db.QueryRow(queryEncryptionKeyParams).Scan(&paramsString)
	switch {
	case reader.err == nil:
	case errors.Is(reader.err, sql.ErrNoRows):
		reader.err = ErrNotEncrypted
		return reader.err

	default:
		return reader.err
	}

	var params *encdec.Params
	params, reader.err = encdec.ParseHeader(bytes.NewReader(paramsString))
	if reader.err != nil {
		return reader.err
	}

	reader.encryptionKey, reader.err = encdec.Key(password, params)
	return reader.err
}

func (reader *Reader) verifyPassword() error {
	var id int
	reader.err = reader.db.QueryRow(queryFileEncryptionKeyIdAny).Scan(&id)
	if reader.err != nil {
		return reader.err
	}

	_, _, err := reader.fileEncryptionKeys(id)
	if err != nil {
		reader.err = ErrWrongPassword
		return reader.err
	}

	return nil
}

func NewReader(databasePath string, password []byte) (*Reader, error) {
	reader := new(Reader)

	reader.db, reader.err = sql.Open("sqlite3", "file:"+databasePath+databaseArgs)
	if reader.err != nil {
		return nil, reader.err
	}

	row := reader.db.QueryRow(queryEncryptionKeyParams)
	reader.encrypted = errors.Is(row.Err(), sql.ErrNoRows)
	if password == nil {
		return reader, nil
	}

	return reader, reader.SetPassword(password)
}

func (reader *Reader) checkError() bool {
	if reader.err == nil || errors.Is(reader.err, io.EOF) {
		return false
	}
	return true
}

func (reader *Reader) IsEncrypted() bool {
	return reader.encrypted
}

func (reader *Reader) SetPassword(password []byte) error {
	if reader.checkError() {
		return reader.err
	}

	reader.err = reader.readEncryptionKey(password)
	if reader.err != nil {
		return reader.err
	}

	return reader.verifyPassword()
}

func (reader *Reader) fileEncryptionKeys(id int) (filenameKey []byte, fileDataKey []byte, err error) {
	var keyEncrypted []byte
	reader.err = reader.db.QueryRow(queryFileEncryptionKeyById, id).Scan(&keyEncrypted)
	if reader.err != nil {
		return nil, nil, reader.err
	}

	var fileMasterKey []byte
	fileMasterKey, reader.err = readFileKey(keyEncrypted, id, reader.encryptionKey)
	if reader.err != nil {
		return nil, nil, reader.err
	}

	filenameKey, fileDataKey = stretchKey(fileMasterKey)
	return filenameKey, fileDataKey, nil
}

func (reader *Reader) Files() (files map[string]*Header, err error) {
	if reader.checkError() {
		return nil, reader.err
	}

	var rows *sql.Rows
	rows, reader.err = reader.db.Query(queryMetadata)
	if reader.err != nil {
		return nil, reader.err
	}
	defer func() {
		err2 := rows.Close()
		if err2 != nil && err == nil {
			reader.err = err2
			err = reader.err
		}
	}()

	files = make(map[string]*Header)
	for rows.Next() {
		header := new(Header)
		var modTime int64
		reader.err = rows.Scan(
			&header.Id,
			&header.Name,
			&header.Size,
			&modTime,
			&header.Compression,
			&header.Encryption,
		)
		if reader.err != nil {
			return nil, reader.err
		}

		header.ModTime = time.Unix(modTime, 0)
		if header.Encryption {
			if reader.encryptionKey == nil {
				files[header.Name] = header
				continue
			}

			filenameKey, _, err := reader.fileEncryptionKeys(header.Id)
			if err != nil {
				return nil, err
			}
			header.Name, reader.err = decryptFilename(header.Name, filenameKey)
			if reader.err != nil {
				return nil, reader.err
			}
		}

		files[header.Name] = header
	}

	return files, nil
}

func (reader *Reader) Open(id int, transaction bool) error {
	if reader.checkError() {
		return reader.err
	}

	var compressed, encrypted bool
	reader.err = reader.db.QueryRow(queryMetadataOptionById, id).Scan(&compressed, &encrypted)
	if reader.err != nil {
		return reader.err
	}

	reader.currReader, reader.err = newDataReader(reader.db, id, transaction)
	if reader.err != nil {
		return reader.err
	}

	if encrypted {
		if reader.encryptionKey == nil {
			reader.err = ErrEmptyPassword
			return reader.err
		}

		var dataKey []byte
		_, dataKey, reader.err = reader.fileEncryptionKeys(id)
		if reader.err != nil {
			return reader.err
		}
		var params encdec.Params
		reader.currReader, reader.err = encdec.NewReader(dataKey, reader.currReader, &params)
		if reader.err != nil {
			return reader.err
		}
	}

	if compressed {
		reader.currReader, reader.err = zstd.NewReader(reader.currReader)
		if reader.err != nil {
			return reader.err
		}
	}

	return nil
}

func (reader *Reader) ReadToFile(id int, filepath string) (err error) {
	if reader.checkError() {
		return reader.err
	}

	if reader.Open(id, true) != nil {
		return reader.err
	}

	var file *os.File
	file, reader.err = os.Create(filepath)
	if reader.err != nil {
		return reader.err
	}
	defer func() {
		err2 := file.Close()
		if err2 != nil && err == nil {
			reader.err = err2
			err = reader.err
		}
	}()

	_, reader.err = io.Copy(file, reader.currReader)
	reader.currReader = nil

	return reader.err
}

func (reader *Reader) Read(p []byte) (int, error) {
	if reader.err != nil {
		return 0, reader.err
	}

	if reader.currReader == nil {
		return 0, ErrNoFileSelected
	}

	var read int
	read, reader.err = reader.currReader.Read(p)
	return read, reader.err
}

type dataReader struct {
	transaction *sql.Tx
	id          int
	currBlock   int
	lastBlock   bool
	rows        *sql.Rows
	buffer      *bytes.Buffer
	err         error
}

func openRows(db *sql.DB, id int) (*sql.Rows, error) {
	rows, err := db.Query(queryDataById, id)
	return rows, err
}

func newDataReader(db *sql.DB, id int, transaction bool) (*dataReader, error) {
	dreader := &dataReader{
		id:     id,
		buffer: new(bytes.Buffer),
	}

	var err error
	if transaction {
		dreader.transaction, err = db.Begin()
		if err != nil {
			return nil, err
		}
	}

	dreader.rows, err = openRows(db, id)
	if err != nil {
		dreader.cleanup()
		return nil, err
	}

	return dreader, nil
}

func (dreader *dataReader) readChunk() error {
	dreader.lastBlock = !dreader.rows.Next()
	var buffer sql.RawBytes
	dreader.rows.Scan(&buffer)
	dreader.buffer = bytes.NewBuffer(buffer)
	dreader.currBlock++
	return dreader.err
}

func (dreader *dataReader) cleanup() {
	if dreader.transaction != nil {
		dreader.transaction.Rollback()
	}
	if dreader.rows != nil {
		dreader.rows.Close()
	}
}

func (dreader *dataReader) Read(p []byte) (int, error) {
	if dreader.err != nil {
		return 0, dreader.err
	}

	var total int
	for len(p) > 0 {
		if dreader.buffer.Len() == 0 {
			if dreader.lastBlock {
				dreader.err = io.EOF
				dreader.cleanup()
				if total == 0 {
					return 0, dreader.err
				}
				return total, nil
			}

			err := dreader.readChunk()
			if err != nil {
				dreader.cleanup()
				return 0, err
			}
		}

		n, _ := dreader.buffer.Read(p)
		total += n
		p = p[n:]
	}

	return total, nil
}

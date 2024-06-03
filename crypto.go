package arc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

const padBlocksize = 100 // PKCS #7 padding range between [1, 155]

func generateFileMasterKey(masterKey []byte, id int) (encryptedKey []byte, fileMasterKey []byte, err error) {
	fileMasterKey = make([]byte, encryptionKeysize)
	_, err = rand.Read(fileMasterKey)
	if err != nil {
		return nil, nil, err
	}

	aead, err := chacha20poly1305.New(masterKey)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce, uint64(id))
	encryptedKey = aead.Seal(nil, nonce, fileMasterKey, nil)

	return encryptedKey, fileMasterKey, nil
}

func readFileKey(encryptedKey []byte, id int, masterKey []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(masterKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce, uint64(id))
	fileMasterKey, err := aead.Open(nil, nonce, encryptedKey, nil)
	return fileMasterKey, err
}

func stretchKey(key []byte) (filenameKey []byte, fileDataKey []byte) {
	keys := make([]byte, 64)
	sha3.ShakeSum256(keys, key)
	return keys[:32], keys[32:]
}

func padFilename(buffer []byte) []byte {
	padSize := padBlocksize - (len(buffer) % padBlocksize)
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(buffer, pad...)
}

func unpadFilename(buffer []byte) ([]byte, error) {
	padSize := buffer[len(buffer)-1]
	count := 0
	for i := len(buffer) - 1; i >= 0; i-- {
		if buffer[i] != padSize {
			break
		}
		count++
		if count == int(padSize) {
			break
		}
	}

	if count != int(padSize) {
		return nil, ErrPadding
	}

	return buffer[:len(buffer)-int(padSize)], nil
}

func encryptFilename(filename string, filenameKey []byte) (encryptedFilename string, err error) {
	aead, err := chacha20poly1305.New(filenameKey)
	if err != nil {
		return "", err
	}

	filenamePadded := padFilename([]byte(filename))
	nonce := make([]byte, aead.NonceSize())
	encryptedFilenameBin := aead.Seal(nil, nonce, filenamePadded, nil)
	return base64.StdEncoding.EncodeToString(encryptedFilenameBin), nil
}

func decryptFilename(filenameEncrypted string, filenameKey []byte) (string, error) {
	filenameEncryptedBin, err := base64.StdEncoding.DecodeString(filenameEncrypted)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.New(filenameKey)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	filename, err := aead.Open(nil, nonce, filenameEncryptedBin, nil)
	if err != nil {
		return "", err
	}

	filename, err = unpadFilename(filename)
	return string(filename), err
}

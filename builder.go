package arc

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// Builder extend [Writer] providing an simpler
// way to write files to a container.
type Builder struct {
	writer      *Writer
	blockSize   int
	compression zstd.EncoderLevel
	password    []byte
	err         error
}

// BuilderOption is an option for creating an builder.
type BuilderOption func(*Builder)

// WithCompressionLevel specifies a compression level to
// be applied for all files written in the container.
func WithCompressionLevel(level zstd.EncoderLevel) BuilderOption {
	return func(builder *Builder) {
		builder.compression = level
	}
}

// WithPassword will use password as the password for
// all files written in the container
func WithPassword(password []byte) BuilderOption {
	return func(builder *Builder) {
		builder.password = password
	}
}

// NewBuilder creates a new Builder and a container with name databasePath
// and the provided options.
func NewBuilder(databasePath string, options ...BuilderOption) (*Builder, error) {
	builder := new(Builder)
	builder.blockSize = DefaultBlocksize
	for _, option := range options {
		option(builder)
	}

	var err error
	builder.writer, err = NewWriter(databasePath, DefaultBlocksize, builder.password)
	return builder, err
}

// InsertFile inserts the path file in the container, using
// the builder's configuration.
func (builder Builder) InsertFile(path string) error {
	return builder.writer.WriteFile(
		&Header{
			Name:        filepath.Base(path),
			Compression: builder.compression,
			Encryption:  builder.password != nil,
		},
		path,
	)
}

func (builder Builder) walkDir(folderPath string) fs.WalkDirFunc {
	return func(path string, dir fs.DirEntry, err error) error {
		if path == "." {
			return nil
		}
		if err != nil {
			log.Printf("not adding %s: %v\n", path, err)
			return nil
		}
		if dir.IsDir() {
			return filepath.SkipDir
		}

		filePath := folderPath + "/" + path
		fmt.Println(filePath)
		return builder.InsertFile(filePath)
	}
}

// InsertDir inserts all files from folderPath, ignoring subdirectories.
func (builder Builder) InsertDir(folderPath string) error {
	if builder.err != nil {
		return builder.err
	}

	rootFs := os.DirFS(folderPath)
	err := fs.WalkDir(rootFs, ".", builder.walkDir(folderPath))
	if err != nil {
		return fmt.Errorf("walking dir %s: %w", folderPath, err)
	}
	return nil
}

func (builder *Builder) Close() error {
	if builder.err != nil {
		return builder.err
	}

	builder.err = errors.New("builder already closed")
	return nil
}

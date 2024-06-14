package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	"github.com/bernardo1r/arc"
	"github.com/bernardo1r/arc/internal/builder"

	"github.com/klauspost/compress/zstd"
	_ "github.com/mattn/go-sqlite3"
)

const (
	dbExtesion = ".arc"
)

const usage = `Usage: arc [INPUT_FOLDER]

This executable is a demo of the library. It will put all files of the provided
directory into an arc container, only files in the root directory will be added.
Then, it 'extracts' the container to a new folder.`

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func fatalUsage() {
	flag.Usage()
	os.Exit(1)
}

func mustBeFolder(folderpath string) {
	info, err := os.Stat(folderpath)
	if err != nil {
		log.Fatalln(err)
	}

	if !info.IsDir() {
		log.Fatalf("%s is not a folder\n", folderpath)
	}
}

func createOrTruncateFolder(folderpath string) error {

	err := os.Mkdir(folderpath, 0775)
	if err == nil {
		return nil
	}

	if errors.Is(err, os.ErrExist) {
		err = os.RemoveAll(folderpath)
		if err != nil {
			return err
		}

		err = os.Mkdir(folderpath, 0775)
	}

	return err
}

func main() {
	file, err := os.Create("cmd/default.pgo")
	checkError(err)
	defer file.Close()
	err = pprof.StartCPUProfile(file)
	checkError(err)
	defer pprof.StopCPUProfile()

	log.SetFlags(0)
	flag.Usage = func() {
		log.Println(usage)
		flag.PrintDefaults()
	}
	if len(os.Args) == 1 {
		fatalUsage()
	}
	flag.Parse()
	switch nFlags := flag.NArg(); {
	case nFlags == 0:
		log.Fatalln("One folder path is required")
	case nFlags > 1:
		log.Fatalln("Only one folder path can be provided")
	}

	folderPath := filepath.Clean(flag.Arg(0))
	mustBeFolder(folderPath)

	start := time.Now()
	arcBuilder, err := builder.NewBuilder(
		filepath.Base(folderPath)+dbExtesion,
		builder.WithCompressionLevel(zstd.SpeedBetterCompression),
		builder.WithPassword([]byte("hello motto")),
	)
	checkError(err)

	err = arcBuilder.InsertDir(folderPath)
	checkError(err)

	err = arcBuilder.Close()
	checkError(err)
	tot := time.Since(start)
	fmt.Printf("Time to write to container: %v\n\n", tot)

	newFolderPath := filepath.Base(folderPath) + "_opened"
	err = createOrTruncateFolder(newFolderPath)
	checkError(err)

	start = time.Now()
	reader, err := arc.NewReader(
		filepath.Base(folderPath)+dbExtesion,
		[]byte("hello motto"),
	)
	checkError(err)

	files, err := reader.Files()
	checkError(err)

	for filename, header := range files {
		filename = filepath.Join(newFolderPath, filename)
		fmt.Printf("Putting %s\n", filename)
		err = reader.ReadToFile(header.Id, filename)
		checkError(err)
	}
	tot = time.Since(start)

	fmt.Printf("Time to write files from container: %v\n", tot)
}

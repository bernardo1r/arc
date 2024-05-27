package main

import (
	"arc"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
	_ "github.com/mattn/go-sqlite3"
)

const (
	dbExtesion = ".arc"
	dbArgs     = "_foreign_keys=on"
)

const usage = `Usage: arc [INPUT_FOLDER]

Put all files of the provided folder into an arc file.
Only files in the root folder will be added.`

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

	err := os.Mkdir(folderpath, 0666)
	if err == nil {
		return nil
	}

	if errors.Is(err, os.ErrExist) {
		err = os.RemoveAll(folderpath)
		if err != nil {
			return err
		}

		err = os.Mkdir(folderpath, 0666)
	}

	return err
}

func main() {
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
	builder, err := arc.NewBuilder(
		filepath.Base(folderPath)+dbExtesion,
		dbArgs,
		arc.WithCompressionLevel(zstd.SpeedBetterCompression),
		arc.WithPassword([]byte("hello motto")),
	)
	checkError(err)

	err = builder.InsertDir(folderPath)
	checkError(err)

	err = builder.Close()
	checkError(err)
	tot := time.Since(start)
	fmt.Printf("Time to write to container: %v\n\n", tot)

	newFolderPath := filepath.Base(folderPath) + "_opened"
	err = createOrTruncateFolder(newFolderPath)
	checkError(err)

	start = time.Now()
	reader, err := arc.NewReader(
		filepath.Base(folderPath)+dbExtesion,
		dbArgs,
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

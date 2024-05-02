package main

import (
	"arc"
	"flag"
	"log"
	"os"
	"path/filepath"

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
		log.Fatalln(info)
	}
	if !info.IsDir() {
		log.Fatalf("%s is not a folder\n", folderpath)
	}
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

	builder, err := arc.NewBuilder(
		filepath.Base(folderPath)+dbExtesion,
		dbArgs,
		arc.WithCompressionLevel(zstd.SpeedBetterCompression),
	)
	checkError(err)
	defer func() {
		checkError(builder.Close())
	}()
	err = builder.InsertDir(folderPath)
	checkError(err)
}

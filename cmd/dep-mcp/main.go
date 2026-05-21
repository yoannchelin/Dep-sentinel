package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/leazelaya/dep-sentinel/internal/mcpserver"
	"github.com/leazelaya/dep-sentinel/internal/store"
)

func main() {
	fs := flag.NewFlagSet("dep-mcp", flag.ExitOnError)
	dbPath := fs.String("db", "", "Path to dep-sentinel SQLite DB (required)")
	_ = fs.Parse(os.Args[1:])

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "dep-mcp: --db is required")
		os.Exit(1)
	}

	s, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dep-mcp: open db: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	srv := mcpserver.New(s)
	if err := srv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "dep-mcp: %v\n", err)
		os.Exit(1)
	}
}

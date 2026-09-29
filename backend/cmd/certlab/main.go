package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"certlab/internal/lab"
)

func main() {
	dir := os.Getenv("CERTLAB_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".certlab-experiment")
	}
	store, err := lab.NewStore(dir)
	if err != nil {
		log.Fatalf("open experiment area: %v", err)
	}
	// Auto-bootstrap the first-round self-contained test chain so reopening the
	// app restores the same experiment (empty area is seeded exactly once).
	if err := store.Bootstrap(); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	addr := os.Getenv("CERTLAB_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8787"
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", lab.NewAPI(store).Handler())
	log.Printf("cert lifecycle lab on http://%s (experiment area: %s)", addr, dir)
	log.Fatal(http.ListenAndServe(addr, mux))
}

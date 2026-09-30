package main

import (
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"

	"certlab/internal/api"
	"certlab/internal/pki"
)

func main() {
	addr := flag.String("addr", envOr("CERTLAB_ADDR", ":8080"), "listen address")
	dataDir := flag.String("data", envOr("CERTLAB_DATA", "./data"), "evidence/data directory")
	webDir := flag.String("web", envOr("CERTLAB_WEB", "./web"), "static web directory")
	flag.Parse()

	lab := pki.NewLab()
	if err := pki.SeedScenarios(lab); err != nil {
		log.Fatalf("seed scenarios: %v", err)
	}
	ev, err := pki.NewEvidenceStore(*dataDir)
	if err != nil {
		log.Fatalf("evidence store: %v", err)
	}

	var webHandler http.Handler
	if st, err := os.Stat(*webDir); err == nil && st.IsDir() {
		sub, err := fs.Sub(os.DirFS(*webDir), ".")
		if err != nil {
			log.Fatal(err)
		}
		webHandler = http.FileServer(http.FS(sub))
		log.Printf("serving frontend from %s", *webDir)
	} else {
		log.Printf("web directory %q not found; API-only mode", *webDir)
	}

	srv := api.NewServer(lab, ev, webHandler)
	log.Printf("certificate lifecycle lab listening on %s", *addr)
	if err := http.ListenAndServe(*addr, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

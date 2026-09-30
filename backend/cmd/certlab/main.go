package main

import (
	"log"

	"certlab/internal/pki"
	"certlab/internal/server"
)

func main() {
	lab := pki.NewLab()
	if err := pki.LoadSamples(lab); err != nil {
		log.Fatalf("load samples: %v", err)
	}
	srv := server.New(lab)
	log.Println("certificate lifecycle lab on http://localhost:8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

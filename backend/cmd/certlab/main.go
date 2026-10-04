package main

import (
	"log"
	"os"

	"certlab/internal/pki"
	"certlab/internal/server"
)

func main() {
	storePath := os.Getenv("CERTLAB_STATE")
	if storePath == "" {
		storePath = "data/lab-state.json"
	}
	lab, err := pki.LoadLab(storePath)
	if err != nil {
		log.Fatalf("load saved lab: %v", err)
	}
	if lab == nil {
		lab = pki.NewLab()
		if err := pki.LoadSamples(lab); err != nil {
			log.Fatalf("load samples: %v", err)
		}
		log.Printf("no saved state, loaded samples")
	} else {
		log.Printf("restored saved lab from %s", storePath)
	}
	if err := lab.SetStore(storePath); err != nil {
		log.Fatalf("enable persistence: %v", err)
	}
	srv := server.New(lab)
	log.Println("certificate lifecycle lab on http://localhost:8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

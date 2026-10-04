package main

import (
	"log"
	"os"

	"certlab/internal/pki"
	"certlab/internal/server"
)

func main() {
	// The lab snapshot keeps every frozen report together with the exact
	// material versions it used; reopening restores them unchanged.
	statePath := os.Getenv("CERTLAB_STATE")
	if statePath == "" {
		statePath = "certlab-state.json"
	}
	lab, err := pki.LoadLab(statePath)
	if err != nil {
		lab = pki.NewLab()
		if err := pki.LoadSamples(lab); err != nil {
			log.Fatalf("load samples: %v", err)
		}
		if err := lab.Save(statePath); err != nil {
			log.Fatalf("save initial state: %v", err)
		}
		log.Printf("initialized sample lab, state saved to %s", statePath)
	} else {
		log.Printf("restored lab state from %s", statePath)
	}
	srv := server.New(lab, statePath)
	log.Println("certificate lifecycle lab on http://localhost:8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"github.com/FilinItPark/simple-gw-go/pkg/config"
	handlerManager "github.com/FilinItPark/simple-gw-go/pkg/handler"
	"log"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <gateway>", os.Args[0])
	}

	configPath := os.Args[1]

	cfg, err := config.ReadConfig(configPath)

	if err != nil {
		log.Fatal(err)
	}

	handler := handlerManager.CreateHandler(cfg)

	http.Handle("/", handler)

	log.Println("Starting gateway server on port 5001")

	err = http.ListenAndServe(":5001", nil)
	if err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"log"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("../docs"))
	http.Handle("/", fs)
	log.Println("Serving HTML at http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
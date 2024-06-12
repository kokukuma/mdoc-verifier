package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	challenge := http.FileServer(http.Dir("./cmd/client/well-known/"))
	r.PathPrefix("/.well-known/").Handler(http.StripPrefix("/.well-known/", challenge))

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./cmd/client/")))

	serverAddress := ":8081"
	log.Println("starting web client at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

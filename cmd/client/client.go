package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	tpl := template.Must(template.ParseFiles(filepath.Join("cmd", "client", "temprate.js")))
	r.HandleFunc("/index.js", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			ServerDomain string
		}{
			ServerDomain: os.Getenv("SERVER_DOMAIN"),
		}

		w.Header().Set("Content-Type", "application/javascript")
		if err := tpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	challenge := http.FileServer(http.Dir("./cmd/client/well-known/"))
	r.PathPrefix("/.well-known/").Handler(http.StripPrefix("/.well-known/", challenge))
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./cmd/client/")))

	serverAddress := ":8081"
	log.Println("starting web client at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

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

	jsTemplate := template.Must(template.ParseFiles(filepath.Join("cmd", "client", "index.js")))
	r.HandleFunc("/index.js", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			ServerDomain string
		}{
			ServerDomain: os.Getenv("SERVER_DOMAIN"),
		}

		w.Header().Set("Content-Type", "application/javascript")
		if err := jsTemplate.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	
	templateJsTemplate := template.Must(template.ParseFiles(filepath.Join("cmd", "client", "temprate.js")))
	r.HandleFunc("/temprate.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		if err := templateJsTemplate.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	
	htmlTemplate := template.Must(template.ParseFiles(filepath.Join("cmd", "client", "index.html")))
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			ServerDomain string
		}{
			ServerDomain: os.Getenv("SERVER_DOMAIN"),
		}

		w.Header().Set("Content-Type", "text/html")
		if err := htmlTemplate.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	challenge := http.FileServer(http.Dir("./cmd/client/well-known/"))
	r.PathPrefix("/.well-known/").Handler(http.StripPrefix("/.well-known/", challenge))
	// Serve static files not handled by specific routes
	fs := http.FileServer(http.Dir("./cmd/client/"))
	r.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip serving index.html, temprate.js and index.js as static files
		// since we have specific handlers for them
		if r.URL.Path == "/" || r.URL.Path == "/index.js" || r.URL.Path == "/temprate.js" {
			return
		}
		http.StripPrefix("/", fs).ServeHTTP(w, r)
	}))

	serverAddress := ":8081"
	log.Println("starting web client at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

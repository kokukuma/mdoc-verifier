package main

import (
	"log"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kokukuma/mdoc-verifier/internal/server"
)

func main() {
	srv := server.NewServer()

	r := mux.NewRouter()
	r.Use(handlers.CORS(
		handlers.AllowedMethods([]string{"POST", "GET", "DELETE"}),
		handlers.AllowedHeaders([]string{"content-type"}),
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowCredentials(),
	))

	r.HandleFunc("/getIdentityRequest", srv.GetIdentityRequest).Methods("POST", "OPTIONS")
	r.HandleFunc("/verifyIdentityResponse", srv.VerifyIdentityResponse).Methods("POST", "OPTIONS")

	// For EUDIW
	r.HandleFunc("/wallet/startIdentityRequest", srv.StartIdentityRequest).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/wallet/request.jwt/{sessionid}", srv.RequestJWT).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/wallet/jwks.json", srv.JWKS).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/wallet/direct_post", srv.DirectPost).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/wallet/finishIdentityRequest", srv.FinishIdentityRequest).Methods("GET", "POST", "OPTIONS")

	// 証明書管理API
	certRouter := r.PathPrefix("/api/certificates").Subrouter()
	certRouter.HandleFunc("", srv.ListCertificatesHandler).Methods("GET", "OPTIONS")
	certRouter.HandleFunc("/{filename}", srv.GetCertificateHandler).Methods("GET", "OPTIONS")
	certRouter.HandleFunc("", srv.AddCertificateHandler).Methods("POST", "OPTIONS")
	certRouter.HandleFunc("/json", srv.AddCertificateJSONHandler).Methods("POST", "OPTIONS")
	certRouter.HandleFunc("/{filename}", srv.DeleteCertificateHandler).Methods("DELETE", "OPTIONS")
	certRouter.HandleFunc("/reload", srv.ReloadCertificatesHandler).Methods("POST", "OPTIONS")
	
	// クライアント証明書チェーンAPI
	r.HandleFunc("/api/client-cert-chain", srv.GetClientCertChainHandler).Methods("GET", "OPTIONS")

	serverAddress := ":8080"
	log.Println("starting fido server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

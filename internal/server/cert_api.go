package server

import (
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"
)

// ListCertificatesHandler returns a list of all certificates
func (s *Server) ListCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	certs, err := s.certManager.ListCertificates()
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to list certificates: %v", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, certs, http.StatusOK)
}

// GetCertificateHandler returns a specific certificate
func (s *Server) GetCertificateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := vars["filename"]

	info, pemData, err := s.certManager.GetCertificate(filename)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to get certificate: %v", err), http.StatusNotFound)
		return
	}

	// Return both certificate info and PEM data
	response := struct {
		Info    *CertInfo `json:"info"`
		PEMData string    `json:"pem_data"`
	}{
		Info:    info,
		PEMData: string(pemData),
	}

	jsonResponse(w, response, http.StatusOK)
}

// AddCertificateHandler adds a new certificate
func (s *Server) AddCertificateHandler(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (max 1MB)
	err := r.ParseMultipartForm(1 << 20)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Get certificate data
	file, fileHeader, err := r.FormFile("certificate")
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to get certificate file: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Use the original uploaded filename
	filename := fileHeader.Filename

	certData, err := io.ReadAll(file)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to read certificate data: %v", err), http.StatusInternalServerError)
		return
	}

	// Add certificate
	err = s.certManager.AddCertificate(filename, certData)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to add certificate: %v", err), http.StatusBadRequest)
		return
	}

	jsonResponse(w, map[string]string{"message": "Certificate added successfully"}, http.StatusOK)
}

// AddCertificateJSONHandler adds a new certificate from JSON data
func (s *Server) AddCertificateJSONHandler(w http.ResponseWriter, r *http.Request) {
	// Parse JSON request
	var req struct {
		Filename string `json:"filename"`
		PEMData  string `json:"pem_data"`
	}

	if err := parseJSON(r, &req); err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	if req.PEMData == "" {
		jsonErrorResponse(w, fmt.Errorf("certificate data is required"), http.StatusBadRequest)
		return
	}

	// Add certificate - filename is optional
	err := s.certManager.AddCertificate(req.Filename, []byte(req.PEMData))
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to add certificate: %v", err), http.StatusBadRequest)
		return
	}

	jsonResponse(w, map[string]string{"message": "Certificate added successfully"}, http.StatusOK)
}

// DeleteCertificateHandler deletes a certificate
func (s *Server) DeleteCertificateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := vars["filename"]

	err := s.certManager.DeleteCertificate(filename)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to delete certificate: %v", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"message": "Certificate deleted successfully"}, http.StatusOK)
}

// ReloadCertificatesHandler reloads all certificates
func (s *Server) ReloadCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	err := s.certManager.ReloadCertificates()
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to reload certificates: %v", err), http.StatusInternalServerError)
		return
	}

	// Update global roots variable
	roots = s.certManager.GetCertPool()

	jsonResponse(w, map[string]string{"message": "Certificates reloaded successfully"}, http.StatusOK)
}

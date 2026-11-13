package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
)

//go:embed page.html account.html
var pageFiles embed.FS

var pageTemplate = template.Must(template.ParseFS(pageFiles, "page.html", "account.html"))

type apiInfo struct {
	Name   string   `json:"name"`
	Routes []string `json:"routes"`
}

type healthStatus struct {
	Status string `json:"status"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           newHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	log.Printf("HTTP API listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func newHandler() http.Handler {
	return newAuthService().handler()
}

func (s *authService) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", route("/health", http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthStatus{Status: "ok"})
	}))
	mux.HandleFunc("/api/v1", route("/api/v1", http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, apiInfo{
			Name: "Vulnerability Generation Agent API",
			Routes: []string{
				"GET /health",
				"GET /api/v1",
				"POST /api/v1/register",
				"POST /api/v1/login",
				"POST /api/v1/logout",
				"GET /api/v1/me",
			},
		})
	}))
	mux.HandleFunc("/api/v1/register", route("/api/v1/register", http.MethodPost, s.register))
	mux.HandleFunc("/api/v1/login", route("/api/v1/login", http.MethodPost, s.login))
	mux.HandleFunc("/api/v1/logout", route("/api/v1/logout", http.MethodPost, s.logout))
	mux.HandleFunc("/api/v1/me", route("/api/v1/me", http.MethodGet, s.me))
	mux.HandleFunc("/account", route("/account", http.MethodGet, s.accountPage))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
				return
			}
			s.renderPage(w, http.StatusOK, false)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "not found"})
			return
		}
		s.renderPage(w, http.StatusNotFound, true)
	})
	return mux
}

func route(path, method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "not found"})
			return
		}
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
			return
		}
		handler(w, r)
	}
}

func (s *authService) renderPage(w http.ResponseWriter, status int, notFound bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pageTemplate.ExecuteTemplate(w, "page.html", struct{ NotFound bool }{NotFound: notFound}); err != nil {
		log.Printf("render page: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}

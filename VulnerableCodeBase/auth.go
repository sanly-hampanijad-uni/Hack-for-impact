package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "session"
	sessionLifetime   = 12 * time.Hour
	maxRequestBody    = 4 << 10
)

type authService struct {
	mu       sync.RWMutex
	users    []user
	sessions map[string]session
}

type user struct {
	Username     string
	PasswordHash []byte
}

type session struct {
	Username string
	Expires  time.Time
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type publicUser struct {
	Username string `json:"username"`
}

func newAuthService() *authService {
	return &authService{sessions: make(map[string]session)}
}

func (s *authService) register(w http.ResponseWriter, r *http.Request) {
	input, ok := readCredentials(w, r)
	if !ok {
		return
	}
	if !validUsername(input.Username) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "username must be 3-32 characters using letters, numbers, underscores, or hyphens"})
		return
	}
	if len(input.Password) < 8 || len(input.Password) > 72 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "password must be 8-72 bytes"})
		return
	}

	s.mu.RLock()
	_, exists := s.findUser(input.Username)
	s.mu.RUnlock()
	if exists {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "username is already registered"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not register user"})
		return
	}

	s.mu.Lock()
	if _, exists := s.findUser(input.Username); exists {
		s.mu.Unlock()
		writeJSON(w, http.StatusConflict, errorResponse{Error: "username is already registered"})
		return
	}
	s.users = append(s.users, user{Username: input.Username, PasswordHash: hash})
	s.mu.Unlock()

	if err := s.createSession(w, r, input.Username); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not create session"})
		return
	}
	writeJSON(w, http.StatusCreated, publicUser{Username: input.Username})
}

func (s *authService) login(w http.ResponseWriter, r *http.Request) {
	input, ok := readCredentials(w, r)
	if !ok {
		return
	}

	s.mu.RLock()
	storedUser, exists := s.findUser(input.Username)
	s.mu.RUnlock()
	if !exists || bcrypt.CompareHashAndPassword(storedUser.PasswordHash, []byte(input.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid username or password"})
		return
	}
	if err := s.createSession(w, r, storedUser.Username); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not create session"})
		return
	}
	writeJSON(w, http.StatusOK, publicUser{Username: storedUser.Username})
}

func (s *authService) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *authService) me(w http.ResponseWriter, r *http.Request) {
	username, ok := s.sessionUsername(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "not authenticated"})
		return
	}
	writeJSON(w, http.StatusOK, publicUser{Username: username})
}

func (s *authService) accountPage(w http.ResponseWriter, r *http.Request) {
	username, ok := s.sessionUsername(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.ExecuteTemplate(w, "account.html", publicUser{Username: username}); err != nil {
		http.Error(w, "could not render account page", http.StatusInternalServerError)
	}
}

func (s *authService) findUser(username string) (user, bool) {
	for _, candidate := range s.users {
		if candidate.Username == username {
			return candidate, true
		}
	}
	return user{}, false
}

func (s *authService) createSession(w http.ResponseWriter, r *http.Request, username string) error {
	var tokenBytes [32]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
	expires := time.Now().Add(sessionLifetime)

	s.mu.Lock()
	s.sessions[token] = session{Username: username, Expires: expires}
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *authService) sessionUsername(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.sessions[cookie.Value]
	if !exists {
		return "", false
	}
	if time.Now().After(current.Expires) {
		delete(s.sessions, cookie.Value)
		return "", false
	}
	return current.Username, true
}

func readCredentials(w http.ResponseWriter, r *http.Request) (credentials, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var input credentials
	if err := decoder.Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "request must contain a username and password as JSON"})
		return credentials{}, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "request must contain one JSON object"})
		return credentials{}, false
	}
	if strings.TrimSpace(input.Username) == "" || input.Password == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "username and password are required"})
		return credentials{}, false
	}
	return input, true
}

func validUsername(username string) bool {
	if len(username) < 3 || len(username) > 32 {
		return false
	}
	for _, character := range username {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return false
		}
	}
	return true
}

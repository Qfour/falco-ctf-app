// Package httpx provides shared HTTP helpers for scoreboard sub-handlers.
package httpx

import (
	"encoding/json"
	"net/http"
)

// WriteJSON sets Content-Type and encodes body as JSON.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

package health

import (
	"encoding/json"
	"net/http"
)

// HealthHandler godoc
//
//	@Summary		Health check endpoint
//	@Description	Check if the API is running and healthy
//	@Tags			health
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]string	"API is healthy"
//	@Failure		500	{object}	map[string]string	"Internal server error"
//	@Router			/health [get]
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status":  "online",
		"message": "API is working correctly",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(response)

	if err != nil {
		http.Error(w, "Error on encoding response", http.StatusInternalServerError)
		return
	}
}

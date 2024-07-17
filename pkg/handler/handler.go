package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/FilinItPark/simple-gw-go/pkg/config"
	"io"
	"net/http"
	"strings"
)

type KeycloackResponse struct {
	Active bool `json:"active"`
}

type KeycloackRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

var keycloackConfig = KeycloackRequest{
	ClientSecret: "",
	ClientId:     "",
}

func CreateHandler(cfg *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)

		if token == "" {
			http.Error(w, "Токен пропущен", http.StatusUnauthorized)
			return
		}

		if !validateToken(token) {
			http.Error(w, "Токен некорректный либо истек", http.StatusUnauthorized)
			return
		}

		for _, rule := range cfg.Rules {
			if strings.Contains(r.URL.Path, rule.From) {
				proxyUrl := rule.To + strings.Split(r.URL.Path, rule.From)[1]
				fmt.Println(proxyUrl)
				//http.Redirect(w, r, proxyUrl, http.StatusTemporaryRedirect)
				return
			}
		}

		http.NotFound(w, r)
	})

}

func validateToken(token string) bool {
	requestBody := fmt.Sprintf("token=%s&client_id=%s&client_secret=%s", token, keycloackConfig.ClientId, keycloackConfig.ClientSecret)
	req, err := http.NewRequest("POST", "https://auth.dppmai.ru/realms/group-1/protocol/openid-connect/token/introspect", bytes.NewBuffer([]byte(requestBody)))

	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return false
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return false
	}

	var keycloackResponse KeycloackResponse
	err = json.Unmarshal(body, &keycloackResponse)

	if err != nil {
		return false
	}

	return keycloackResponse.Active
}

func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")

	if bearerToken == "" {
		return bearerToken
	}

	parts := strings.Split(bearerToken, " ")

	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

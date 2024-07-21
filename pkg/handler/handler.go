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
	Active         bool                   `json:"active"`
	ResourceAccess map[string]interface{} `json:"resource_access"`
}

type KeycloackRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

var keycloackConfig = KeycloackRequest{
	ClientSecret: "7TCb2UhbgVpyh186oC6VMe9srakq16Bp",
	ClientId:     "auth-service",
}

func CreateHandler(cfg *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)

		for _, rule := range cfg.Rules {
			if strings.Contains(r.URL.Path, rule.From) {
				if rule.AuthRequired {

					if token == "" {
						http.Error(w, "Токен пропущен", http.StatusUnauthorized)
						return
					}

					active, roles := validateToken(token)

					if !active {
						http.Error(w, "Токен некорректный либо истек", http.StatusUnauthorized)
						return
					}

					if !hasRoles(roles, rule.Roles) {
						http.Error(w, "У вас нет доступа", http.StatusForbidden)
						return
					}
				}

				proxyUrl := rule.To + strings.Split(r.URL.Path, rule.From)[1]
				fmt.Println(proxyUrl)
				//http.Redirect(w, r, proxyUrl, http.StatusTemporaryRedirect)
				return
			}
		}

		http.NotFound(w, r)
	})

}

func hasRoles(rolesFromToken []string, rolesFromRule []string) bool {
	roleMap := make(map[string]bool)

	for _, role := range rolesFromRule {
		roleMap[role] = true
	}

	for _, role := range rolesFromToken {
		if !roleMap[role] {
			return false
		}
	}
	return true
}

func validateToken(token string) (bool, []string) {
	requestBody := fmt.Sprintf("token=%s&client_id=%s&client_secret=%s", token, keycloackConfig.ClientId, keycloackConfig.ClientSecret)
	//req, err := http.NewRequest("POST", "https://auth.dppmai.ru/realms/group-1/protocol/openid-connect/token/introspect", bytes.NewBuffer([]byte(requestBody)))
	req, err := http.NewRequest("POST", "https://lemur-7.cloud-iam.com/auth/realms/grad-project/protocol/openid-connect/token/introspect", bytes.NewBuffer([]byte(requestBody)))

	if err != nil {
		return false, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return false, nil
	}

	var keycloackResponse KeycloackResponse
	err = json.Unmarshal(body, &keycloackResponse)

	if err != nil {
		return false, nil
	}

	roles := extractRoles(keycloackResponse.ResourceAccess)

	return keycloackResponse.Active, roles
}

/*
*
Пробегается по объекту вида:

	 "resource_access": {
			"auth-service": {
				"roles": [
					"admin",
					"user"
				]
			}
		},

@param resourceAccess map[string]interface{} объект содержащий информацию о ролях пользователя
@return roles []string список ролей пользователя
*/
func extractRoles(resourceAccess map[string]interface{}) (roles []string) {
	for _, value := range resourceAccess {
		if access, ok := value.(map[string]interface{}); ok {
			if r, ok := access["roles"]; ok {
				if roleList, ok := r.([]interface{}); ok {
					for _, role := range roleList {
						if roleStr, ok := role.(string); ok {
							roles = append(roles, roleStr)
						}
					}
				}
			}
		}
	}

	return roles
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

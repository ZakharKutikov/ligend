package panel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type Auth struct {
	jwtSecret []byte
	db        *DB
}

func NewAuth(db *DB) (*Auth, error) {
	secretStr, err := db.GetPanelConfig("jwt_secret")
	if err != nil {
		return nil, err
	}
	var secret []byte
	if secretStr == "" {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		secretStr = hex.EncodeToString(secret)
		if err := db.SetPanelConfig("jwt_secret", secretStr); err != nil {
			return nil, err
		}
	} else {
		secret, err = hex.DecodeString(secretStr)
		if err != nil {
			return nil, err
		}
	}
	return &Auth{jwtSecret: secret, db: db}, nil
}

func (a *Auth) GenerateToken(username string) (string, error) {
	exp := time.Now().Add(24 * time.Hour).Unix()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadData, _ := json.Marshal(map[string]interface{}{"sub": username, "exp": exp})
	payload := base64.RawURLEncoding.EncodeToString(payloadData)

	sig := a.sign(header + "." + payload)
	return header + "." + payload + "." + sig, nil
}

func (a *Auth) ValidateToken(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token format")
	}

	sig := a.sign(parts[0] + "." + parts[1])
	if !hmac.Equal([]byte(sig), []byte(parts[2])) {
		return "", errors.New("invalid signature")
	}

	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadData, &claims); err != nil {
		return "", err
	}

	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() > int64(exp) {
		return "", errors.New("token expired")
	}

	username, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("invalid subject")
	}

	return username, nil
}

func (a *Auth) sign(data string) string {
	h := hmac.New(sha256.New, a.jwtSecret)
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (a *Auth) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"success":false,"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		_, err := a.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, `{"success":false,"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *Auth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"success":false,"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	if !a.db.ValidateUser(req.Username, req.Password) {
		http.Error(w, `{"success":false,"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token, err := a.GenerateToken(req.Username)
	if err != nil {
		http.Error(w, `{"success":false,"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"token":      token,
			"expires_at": time.Now().Add(24 * time.Hour).Unix(),
		},
	})
}

package main

import (
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

import "net/http"

type Tokens struct {
	ps *PostgresService
	es *EmailService
}

func (t Tokens) GetTokensHandler(w http.ResponseWriter, r *http.Request) {
	ip := getUserIP(r)
	guid := chi.URLParam(r, "guid")
	if guid == "" {
		http.Error(w, "GUID is required", http.StatusBadRequest)
		return
	}
	err := t.ps.DeleteRefreshTokenByGUID(guid)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.CreateTokens(w, guid, ip)
}

func (t Tokens) RefreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	ip := getUserIP(r)
	cookieAccess, err := r.Cookie("access_token")
	if err != nil {
		log.Println(err)
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}
	cookieRefresh, err := r.Cookie("refresh_token")
	if err != nil {
		log.Println(err)
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}

	accessToken, err := validateJWT(cookieAccess.Value)
	if err != nil {
		log.Println(err)
		http.Error(w, "Something went wrong", http.StatusUnauthorized)
		return
	}

	claims := accessToken.Claims.(jwt.MapClaims)

	accessExpiresAt := time.Unix(int64(claims["ExpiresAt"].(float64)), 0)
	if !time.Now().After(accessExpiresAt) {
		log.Println("Token not expired")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Access token is still valid"))
		return
	}

	accessTokenHash := claims["RefreshTokenHash"]
	accessTokenHashStr := accessTokenHash.(string)
	refreshToken := cookieRefresh.Value

	if err = bcrypt.CompareHashAndPassword([]byte(accessTokenHashStr), []byte(refreshToken)); err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	refreshTokenData, err := t.ps.GetRefreshToken(accessTokenHashStr)
	if err != nil {
		log.Println(err)
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}

	if ip != refreshTokenData.IP {
		//get user email by guid
		err = t.es.SuspiciousRefresh("user@mock.com", ip)
		if err != nil {
			log.Println(err)
		}
		log.Println("Warning Email sent")
	}

	if time.Now().After(refreshTokenData.ExpiresAt) {
		http.Error(w, "Something went wrong", http.StatusUnauthorized)
	}
	err = t.ps.DeleteRefreshToken(refreshTokenData.Hash)
	if err != nil {
		log.Println(err)
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}

	guid := claims["guid"].(string)
	if ip != refreshTokenData.IP {
		err = t.ps.UpdateIP(accessTokenHashStr, ip)
		if err != nil {
			log.Println(err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
	}
	t.CreateTokens(w, guid, ip)
}

func (t Tokens) CreateTokens(w http.ResponseWriter, guid, ip string) {
	refreshToken, err := NewToken()
	if err != nil {
		log.Println(err)
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}
	encryptedRefreshToken, err := t.ps.CreateRefreshToken(ip, guid, refreshToken)
	if err != nil {
		log.Println(err)
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}

	accessToken, err := CreateAccessToken(guid, encryptedRefreshToken)
	if err != nil {
		log.Println(err)
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}

	cookieAccess := http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
		Secure:   true,
	}

	cookieRefresh := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Expires:  time.Now().Add(720 * time.Hour),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookieAccess)
	http.SetCookie(w, &cookieRefresh)
}

func getUserIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-Ip")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	if strings.Contains(ip, ":") {
		ip, _, _ = net.SplitHostPort(ip)
	}
	return ip
}

func CreateAccessToken(guid, refresh string) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", errors.New("jwt secret is not set")
	}
	claims := &jwt.MapClaims{
		"ExpiresAt":             time.Now().Add(1 * time.Minute).Unix(),
		"guid":                  guid,
		"RefreshTokenHash": refresh,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString([]byte(secret))
	return token, err
}

func validateJWT(tokenString string) (*jwt.Token, error) {
	secret := os.Getenv("JWT_SECRET")
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
}


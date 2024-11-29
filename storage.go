package main

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type PostgresService struct {
	DB *sql.DB
}

type RefreshToken struct {
	Hash string
	GUID string
	IP        string
	ExpiresAt time.Time
}

func (s *PostgresService) CreateRefreshToken(ip, guid, token string) (string, error) {
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("creating refresh token: %w", err)
	}
	rt := RefreshToken{
		Hash:      string(tokenHash),
		IP:        ip,
		GUID:      guid,
		ExpiresAt: time.Now().Add(720 * time.Hour),
	}
	query := `INSERT INTO refresh_tokens(token_hash, ip, user_guid, expires_at) values ($1, $2, $3, $4)`
	_, err = s.DB.Exec(query, rt.Hash, rt.IP, rt.GUID, rt.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("creating refresh token: %w", err)
	}
	return rt.Hash, nil
}

func (s *PostgresService) DeleteRefreshToken(tokenHash string) error {
	query := `DELETE FROM refresh_tokens WHERE token_hash = $1`
	_, err := s.DB.Exec(query, tokenHash)
	if err != nil {
		return fmt.Errorf("deleting refresh token: %w", err)
	}
	return nil
}

func (s *PostgresService) GetRefreshToken(tokenHash string) (*RefreshToken, error) {
	query := `SELECT user_guid, ip, expires_at FROM refresh_tokens WHERE token_hash = $1`
	row := s.DB.QueryRow(query, tokenHash)
	var token RefreshToken
	token.Hash = tokenHash
	err := row.Scan(&token.GUID, &token.IP, &token.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("getting refresh token: %w", err)
	}
	return &token, nil
}

func (s *PostgresService) UpdateIP(tokenHash, ip string) error {
	query := `UPDATE refresh_tokens SET ip = $1 WHERE token_hash = $2`
	_, err := s.DB.Exec(query, ip, tokenHash)
	if err != nil {
		return fmt.Errorf("updating ip: %w", err)
	}
	return nil
}

func (s *PostgresService) DeleteRefreshTokenByGUID(guid string) error {
	query := `DELETE FROM refresh_tokens WHERE user_guid = $1`
	_, err := s.DB.Exec(query, guid)
	if err != nil {
		return fmt.Errorf("deleting refresh token: %w", err)
	}
	return nil
}

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
	SSLMode  string
}

func (cfg PostgresConfig) ConnectionString() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database, cfg.SSLMode)
}

func Open(config PostgresConfig) (*sql.DB, error) {
	db, err := sql.Open("pgx", config.ConnectionString())
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return db, nil
}


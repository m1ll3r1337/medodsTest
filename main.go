package main

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"net/http"
	"os"
	"strconv"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}
	postgresCfg := PostgresConfig{
		Host:     os.Getenv("PSQL_HOST"),
		Port:     os.Getenv("PSQL_PORT"),
		User:     os.Getenv("PSQL_USER"),
		Password: os.Getenv("PSQL_PASSWORD"),
		Database: os.Getenv("PSQL_DATABASE"),
		SSLMode:  os.Getenv("PSQL_SSLMODE"),
	}
	if postgresCfg.Host == "" && postgresCfg.Port == "" {
		panic("Invalid config provided")
	}

	db, err := Open(postgresCfg)
	if err != nil {
		panic(err)
	}
	ps := &PostgresService{
		DB: db,
	}
	smtpCfg := SMTPConfig{
		Host:     os.Getenv("SMTP_HOST"),
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
	}
	portStr := os.Getenv("SMTP_PORT")
	smtpCfg.Port, err = strconv.Atoi(portStr)
	if err != nil {
		panic(err)
	}
	es := NewEmailService(smtpCfg)
	t := Tokens{
		ps: ps,
		es: es,
	}

	r := chi.NewRouter()
	r.Get("/tokens/{guid}", t.GetTokensHandler)
	r.Get("/refresh", t.RefreshTokensHandler)

	fmt.Println("Listening on :8080...")
	err = http.ListenAndServe(":8080", r)
	if err != nil {
		panic(err)
	}
}

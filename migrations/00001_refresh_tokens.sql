-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS refresh_tokens
(
    id       SERIAL PRIMARY KEY,
    token_hash TEXT NOT NULL,
    user_guid UUID NOT NULL UNIQUE ,
    ip INET NOT NULL,
    expires_at TIMESTAMP NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE refresh_tokens;
-- +goose StatementEnd

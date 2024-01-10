ALTER TABLE users
ADD COLUMN claim_token VARCHAR(255) UNIQUE,
ADD COLUMN user_creator INT,
ADD COLUMN token_expiration DATETIME;


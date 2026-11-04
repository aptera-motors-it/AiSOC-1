-- Each user has at most one refresh token that can be exchanged.  The JWT
-- carries this UUID; a successful exchange atomically replaces it.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS refresh_token_jti uuid;

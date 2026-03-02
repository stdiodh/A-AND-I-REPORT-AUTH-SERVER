CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL,
    user_track VARCHAR(16) NOT NULL,
    cohort INTEGER NOT NULL,
    cohort_order INTEGER NOT NULL,
    public_code VARCHAR(16) NOT NULL,
    force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMP NULL,
    nickname VARCHAR(40) NULL,
    profile_image_url VARCHAR(2048) NULL,
    profile_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX ux_users_public_code ON users(public_code);

CREATE TABLE user_invites (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_user_invites_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

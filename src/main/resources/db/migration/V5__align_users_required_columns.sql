ALTER TABLE users
    ADD COLUMN IF NOT EXISTS user_track VARCHAR(16),
    ADD COLUMN IF NOT EXISTS cohort INTEGER,
    ADD COLUMN IF NOT EXISTS cohort_order INTEGER,
    ADD COLUMN IF NOT EXISTS public_code VARCHAR(16);

UPDATE users
SET user_track = 'NO'
WHERE user_track IS NULL OR BTRIM(user_track) = '';

UPDATE users
SET cohort = 0
WHERE cohort IS NULL;

UPDATE users
SET cohort_order = 0
WHERE cohort_order IS NULL;

UPDATE users
SET public_code = username
WHERE public_code IS NULL OR BTRIM(public_code) = '';

ALTER TABLE users
    ALTER COLUMN user_track SET DEFAULT 'NO',
    ALTER COLUMN cohort SET DEFAULT 0,
    ALTER COLUMN cohort_order SET DEFAULT 0;

ALTER TABLE users
    ALTER COLUMN user_track SET NOT NULL,
    ALTER COLUMN cohort SET NOT NULL,
    ALTER COLUMN cohort_order SET NOT NULL,
    ALTER COLUMN public_code SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_public_code ON users (public_code);

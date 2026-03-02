ALTER TABLE users
    ADD COLUMN IF NOT EXISTS user_track VARCHAR(16),
    ADD COLUMN IF NOT EXISTS cohort INTEGER,
    ADD COLUMN IF NOT EXISTS cohort_order INTEGER,
    ADD COLUMN IF NOT EXISTS public_code VARCHAR(16);

UPDATE users
SET cohort = COALESCE(cohort, 0);

WITH ranked AS (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY cohort ORDER BY created_at, id) AS rn
    FROM users
)
UPDATE users u
SET cohort_order = COALESCE(u.cohort_order, ranked.rn)
FROM ranked
WHERE u.id = ranked.id;

UPDATE users
SET user_track = COALESCE(user_track, 'NO');

UPDATE users
SET public_code = CONCAT(
    '#',
    CASE
        WHEN role = 'USER' THEN
            CASE user_track
                WHEN 'FL' THEN 'FL'
                WHEN 'SP' THEN 'SP'
                ELSE 'NO'
                END
        WHEN role = 'ORGANIZER' THEN 'OR'
        ELSE 'AD'
        END,
    cohort::TEXT,
    LPAD(cohort_order::TEXT, 2, '0')
)
WHERE public_code IS NULL;

ALTER TABLE users
    ALTER COLUMN user_track SET NOT NULL,
    ALTER COLUMN cohort SET NOT NULL,
    ALTER COLUMN cohort_order SET NOT NULL,
    ALTER COLUMN public_code SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_public_code ON users (public_code);

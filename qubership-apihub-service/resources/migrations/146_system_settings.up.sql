CREATE TABLE IF NOT EXISTS system_settings (
    key varchar PRIMARY KEY,
    value varchar NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_by varchar
);

-- Insert default versionPattern that allows A-Z, a-z, 0-9, _, ., -, ~, space
-- Cannot start or end with spaces, must contain at least one non-space character
INSERT INTO system_settings (key, value)
VALUES ('versionPattern', '^(?!\s)(?=.*\S)[A-Za-z0-9_.\-~ ]+(?<!\s)$');

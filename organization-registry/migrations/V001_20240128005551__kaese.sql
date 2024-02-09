CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    organization BIGINT UNSIGNED NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    admin BOOLEAN DEFAULT(0) NOT NULL,
    CONSTRAINT FOREIGN KEY (organization) REFERENCES organizations(id)
);

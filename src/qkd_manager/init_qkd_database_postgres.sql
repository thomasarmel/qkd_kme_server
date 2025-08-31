/* Uninitialized keys, available for SAEs in this KME and other_kme */
CREATE TABLE IF NOT EXISTS uninit_keys (
    id SERIAL PRIMARY KEY,
    key_uuid TEXT NOT NULL,
    key BYTEA NOT NULL,
    other_kme_id BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_uninitkeys_id_keyuuid ON uninit_keys(id, key_uuid);

CREATE TABLE IF NOT EXISTS saes (
    sae_id BIGINT NOT NULL PRIMARY KEY,
    sae_certificate_serial BYTEA,
    kme_id BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saes_saeid_saecertificateserial ON saes(sae_id, sae_certificate_serial);

/* Keys assigned to SAEs */
CREATE TABLE IF NOT EXISTS keys (
    id SERIAL PRIMARY KEY,
    key_uuid TEXT NOT NULL,
    key BYTEA NOT NULL,
    origin_sae_id BIGINT NOT NULL,
    target_sae_id BIGINT NOT NULL,
    FOREIGN KEY (origin_sae_id) REFERENCES saes(sae_id),
    FOREIGN KEY (target_sae_id) REFERENCES saes(sae_id)
);

CREATE INDEX IF NOT EXISTS idx_keys_id_keyuuid ON keys(id, key_uuid);

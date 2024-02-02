/* Uninitialized keys, available for SAEs in this KME and other_kme */
CREATE TABLE IF NOT EXISTS uninit_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    key_uuid TEXT NOT NULL,
    key BLOB NOT NULL,
    other_kme_id INTEGER NOT NULL
);

/* Keys assigned to SAEs */
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    key_uuid TEXT NOT NULL,
    key BLOB NOT NULL,
    origin_sae_id INTEGER NOT NULL,
    target_sae_id INTEGER NOT NULL,
    FOREIGN KEY (origin_sae_id) REFERENCES saes(sae_id),
    FOREIGN KEY (target_sae_id) REFERENCES saes(sae_id)
);

CREATE TABLE IF NOT EXISTS saes (
    sae_id INTEGER PRIMARY KEY NOT NULL,
    sae_certificate_serial BLOB,
    kme_id INTEGER NOT NULL
);
/* Uninitialized keys, available for SAEs in this KME and other_kme */
CREATE TABLE IF NOT EXISTS uninit_keys (
    id BIGINT NOT NULL AUTO_INCREMENT,
    key_uuid VARCHAR(255) NOT NULL,
    qkd_key BLOB NOT NULL,
    other_kme_id BIGINT NOT NULL,
    PRIMARY KEY (id),
    INDEX (id, key_uuid)
);


CREATE TABLE IF NOT EXISTS saes (
    sae_id BIGINT NOT NULL AUTO_INCREMENT,
    sae_certificate_serial BLOB,
    kme_id BIGINT NOT NULL,
    PRIMARY KEY (sae_id),
    INDEX (sae_id, sae_certificate_serial(255))
);


/* Keys assigned to SAEs */
CREATE TABLE IF NOT EXISTS activated_keys (
    id BIGINT NOT NULL AUTO_INCREMENT,
    key_uuid VARCHAR(255) NOT NULL,
    qkd_key BLOB NOT NULL,
    origin_sae_id BIGINT NOT NULL,
    target_sae_id BIGINT NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (origin_sae_id) REFERENCES saes(sae_id),
    FOREIGN KEY (target_sae_id) REFERENCES saes(sae_id),
    INDEX (id, key_uuid)
);

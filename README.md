# ETSI QKD KME server implementation

*The following repository contains an implementation proposal for the KME (Key Management Entity) server defined in the [ETSI QKD standard](docs/etsi_qkd_standard_definition.pdf).*

---

## Installation

### Compilation

Install Rust programming language, as explained at https://www.rust-lang.org/tools/install.

```bash
git clone https://github.com/thomasarmel/qkd_kme_server.git
cd qkd_kme_server
cargo test
cargo build --release
```

### Manual testing

I already generated some certificates for your tests, but you can obviously generate your own ones.

Simply put [certs/CA-zone1.crt](certs/CA-zone1.crt) into your trusted CA certificates folder and [certs/sae1.pfx](certs/sae1.pfx) into your client certificates store.

---

## SAE authentication

SAEs are authenticated using client certificates. The server checks that the certificate is signed by a trusted CA.

Then SAE is identified using the certificate serial number.

---

## Routes

**Note**: SAE ids are 64 bits integers

---

### GET /api/v1/keys/{slave SAE id}/status

*This route should be called by the master SAE*

Get the status of the QKD key exchange with the slave SAE, ie how much exchanged keys are available.

Id of the calling SAE is automatically retrieved from the client certificate.

Response example:

```json
{
  "source_KME_ID": "1",
  "target_KME_ID": "?? TODO",
  "master_SAE_ID": "1",
  "slave_SAE_ID": "2",
  "key_size": 256,
  "stored_key_count": 1,
  "max_key_count": 10,
  "max_key_per_request": 1,
  "max_key_size": 256,
  "min_key_size": 256,
  "max_SAE_ID_count": 0
}
```

---

### POST /api/v1/keys/{slave SAE id}/enc_keys

*This route should be called by the master SAE*

**Note**: Only one key per request is supported for now.

Retrieve a key already exchanged between the master KME (the one responding) and the slave KME.

It returns the key encoded in base64 and the key ID, that should be sent directly to the slave SAE in order to let it retrieve the key.

Response example:

```json
{
  "keys": [
    {
      "key_ID": "8844cba7-29e1-3251-a50a-25da13e65eea",
      "key": "dGhpc19pc19zZWNyZXRfa2V5XzFfb2ZfMzJfYnl0ZXM="
    }
  ]
}
```

---

### POST /api/v1/keys/{master SAE id}/dec_keys

*This route should be called by the slave SAE*

Retrieve a key already exchanged between the master KME and the slave KME (the one responding), from the key id.

Key id is the one sent by the master KME.

Request example:

```json
{
  "key_IDs": [
    {
      "key_ID": "8844cba7-29e1-3251-a50a-25da13e65eea"
    },
    {
      "key_ID": "8844cba7-29e1-3251-a50a-25da13e65eea"
    }
  ]
}
```

Response example:

```json
{
  "keys": [
    {
      "key_ID": "8844cba7-29e1-3251-a50a-25da13e65eea",
      "key": "dGhpc19pc19zZWNyZXRfa2V5XzFfb2ZfMzJfYnl0ZXM="
    },
    {
      "key_ID": "8844cba7-29e1-3251-a50a-25da13e65eea",
      "key": "dGhpc19pc19zZWNyZXRfa2V5XzFfb2ZfMzJfYnl0ZXM="
    }
  ]
}
```

---

### GET /api/v1/sae/info/me

*This route should be called by any SAE*

Get the information of the calling SAE, identified by its certificate serial number.

If the SAE is not registered, a not found error is returned.

Response example:

```json
{
  "SAE_ID": 1
}
```
# API specifications

---

Below are described the REST API routes exposed by the KME.

For now, our implementation doesn't support 100% of the routes described in 
the [official standard](etsi_qkd_standard_definition.pdf). This is 
considered as future work. The main features are however implemented, and 
should allow you to perform basic QKD key exchanges between SAEs.


**Note**: SAE ids are 64 bits integers

---

## Official API routes


## `GET /api/v1/keys/{slave SAE id}/status`

*This route should be called by the master SAE*

Get the status of the QKD key exchange with the slave SAE, ie how much exchanged keys are available.

ID of the calling SAE is automatically retrieved from the client certificate.

### Response example:

```json
{
  "source_KME_ID": "1",
  "target_KME_ID": "2",
  "master_SAE_ID": "1",
  "slave_SAE_ID": "2",
  "key_size": 256,
  "stored_key_count": 1,
  "max_key_count": 10,
  "max_key_per_request": 10,
  "max_key_size": 256,
  "min_key_size": 256,
  "max_SAE_ID_count": 0
}
```

---

## `POST /api/v1/keys/{slave SAE id}/enc_keys`

*This route should be called by the master SAE*

Retrieve a key already exchanged between the master KME (the one responding) and the slave KME.

It returns the key encoded in base64 and the key ID, that should be sent directly to the slave SAE in order to let it retrieve the key.

By default, only one key is requested (empty request body). You can
request multiple keys by specifying the `number` field in the JSON request
body
(**max 10**):
```json
{
  "number": 3
}
```

### Response example:

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

Or for multiple keys:

```json
{
  "keys": [
      {
          "key_ID": "9768257a-1c59-d255-a93d-d4bb1b693651",
          "key": "zNK/zOIUDAFyuKRM0dSJLLZVYaDTuhzhAIACBgWABfY="
      },
      {
          "key_ID": "80ccede4-05c9-815a-8e80-d151452bcb82",
          "key": "/f8mwVeHSVMWjAAp5GGlSJDJSuB47Agvvo6ta66lIqQ="
      },
      {
           "key_ID": "f6c4a667-23ea-7e58-b07d-95a568d140da",
           "key": "6Db9BONohKETQqFPwIEYMS5h0GmskMickEWbowUQsqs="
       }
   ]
}
```

## `GET /api/v1/keys/{slave SAE id}/enc_keys`

*This route should be called by the master SAE*

Retrieve a key already exchanged between the master KME (the one responding) and the slave KME.

It returns the key encoded in base64 and the key ID, that should be sent directly to the slave SAE in order to let it retrieve the key.

By default, only one key is requested (no query param). You can
request multiple keys by specifying the `number` field in the query parameters
(**max 10**): `GET /api/v1/keys/{slave SAE id}/enc_keys?number=3`

### Response example:

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

Or for multiple keys:

```json
{
  "keys": [
      {
          "key_ID": "9768257a-1c59-d255-a93d-d4bb1b693651",
          "key": "zNK/zOIUDAFyuKRM0dSJLLZVYaDTuhzhAIACBgWABfY="
      },
      {
          "key_ID": "80ccede4-05c9-815a-8e80-d151452bcb82",
          "key": "/f8mwVeHSVMWjAAp5GGlSJDJSuB47Agvvo6ta66lIqQ="
      },
      {
           "key_ID": "f6c4a667-23ea-7e58-b07d-95a568d140da",
           "key": "6Db9BONohKETQqFPwIEYMS5h0GmskMickEWbowUQsqs="
       }
   ]
}
```

## `POST /api/v1/keys/{master SAE id}/dec_keys`

*This route should be called by the slave SAE*

Retrieve a key already exchanged between the master KME and the slave KME (the one responding), from the key id.

Key id is the one sent by the master KME.

### Request example:

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


### Response example:

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

## Additional API routes of our implementation

## `GET /api/v1/sae/info/me`

*This route should be called by any SAE*

Get the information of the calling SAE, identified by its certificate serial number.

If the SAE is not registered, a not found error is returned.

### Response example:

```json
{
  "SAE_ID": 1
}
```


## `GET /api/v1/keys/entropy/total`

*This route should be called by any SAE*

Get the Shannon entropy of all the keys stored in the KME.

:warning: If you notice the entropy is abnormally low, it may be a sign that an attacker compromised the QKD key exchange or the Privacy Amplification process.

### Response example:

```json
{
  "total_entropy": 7.919922493186846
}
```
# Config file

---

KME configuration is done in a file in [JSON5](https://json5.org/) format.

This is a backward-compatible improvement of the JSON format, allowing you 
to write `// comments`, or enter numbers in hexadecimal format (`0xe1` instead 
of `225` for example).

The sections of the configuration file are described below:

### `this_kme`

This object describes the KME itself

- **`id`** *(integer, 64-bit)*  
  Unique ID of the KME in the whole network, as a 64-bit integer.
  
  Please 
  note that SAE and KME IDs are different, meaning a SAE and a KME can share the same ID.

- **`nickname`** *(string, optional)*  
  An optional human-readable name for the KME, such as "`Alice`" or "`Bob`".
  The nickname will appear on the logs in the web UI. If the nickname is 
   not set, the web UI will display "`KME {ID}`".

- **`sqlite_db_path`** *(string)*  
  Path to the SQLite database file.
  The software will create the tables if they do not exist.
  You can specify "`:memory:`" to use an in-memory database.

- **`delete_key_file_after_read`** *(boolean)*  
  If set to `true`, the software will delete the QKD key files after reading them.
  You should probably set it to `true` if you use persistent database (not `:memory:`).

- **`key_directory_to_watch`** *(string)*  
  A directory containing the QKD keys for key exchange between SAEs inside the secure zone. It's not very useful as direct public-key encryption is more suitable for this purpose, but it has to be set for compatibility purpose.

- **`saes_https_interface`** *(object)*  
  This section describes the private HTTPS interface for SAEs inside the secure zone
    - `listen_address` *(string)* — The address to listen SAEs HTTPS requests, such as 
      `10.0.0.2:13000`
      
      :warning: you should avoid using `0.0.0.0` as this interface should be exposed only to the secure zone).
    - `ca_client_cert_path` *(string)* — Path to the `.crt` CA certificate used to 
      authenticate SAEs.
    - `server_cert_path` *(string)* — Path to the `.crt` server certificate (the one 
      you should have added to SAEs trusted certificates store).
    - `server_key_path` *(string)* — Path to the `.key` server private key.

- **`debugging_http_interface`** *(string, optional)*  
  An optional address for the debugging HTTP interface, to be consulted using a web browser (see below). It is only for demonstration purpose and should not be exposed to the public.

- **`kmes_https_interface`** *(object)*  
  This section describes the public HTTPS interface for remote KMEs
    - `listen_address` *(string)* — The address to listen KMEs HTTPS requests, such as 
      `0.0.0.0:13001`.
    - `ca_client_cert_path` *(string)* — Path to the `.crt` CA certificate used to 
      authenticate KMEs.
    - `server_cert_path` *(string)* — Path to the `.crt` server certificate (the one 
      you should have added to KMEs trusted certificates store).
    - `server_key_path` *(string)* — Path to the `.key` server private key.

---

### `other_kmes`

An **array** of objects describing all other KMEs in the network.

Each object contains:

- `id` *(integer, 64-bit)* — Unique ID of the KME in the whole network, as a 64-bit integer.
- `key_directory_to_watch` *(string)* — A directory containing `.cor` QKD key files, 
  after Privacy Amplification between the two zones.
- `inter_kme_bind_address` *(string)* — The address to connect to the other KME via 
  HTTPS, such as `1.2.3.4:14001`.
- `ignore_system_proxy_settings` *(boolean, optional)* — Should be set to 
  `true` if you want to ignore system proxy settings for connection to this 
  remote KME. If not set, default to false.
- `https_client_authentication_certificate` *(string)* — `.pfx` client certificate 
  used to authenticate to the other KME.
- `https_client_authentication_certificate_password` *(string)* — Password for the `.
pfx` client certificate (empty string if no password).

---

### `saes`

An **array** of objects describing all SAEs (either in this secure zone or belonging to remote KMEs).

Each object contains:

- `id` *(integer, 64-bit)* — Unique ID of the SAE in the whole network, as a 64-bit integer.
- `kme_id` *(integer, 64-bit)* — ID of the KME to which the SAE belongs, either ID of this KME 
  or a remote KME.
- `https_client_certificate_serial` — *(array of integers, optional)*
   If SAE belongs to this KME, integer array of the serial number of the `.
   crt` client certificate. As the configuration is in JSON5, you can type the numbers in hexadecimal format.
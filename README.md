# ETSI-compliant Quantum Key Distribution (QKD) Key Management Entity server

*The following repository contains an implementation proposal for the KME (Key Management Entity) server defined in the [ETSI QKD standard](docs/etsi_qkd_standard_definition.pdf) for Quantum Key Distribution.*

---

## Introduction

### Quantum Key Distribution

Cross-datacenter communication is a common use case in the cloud.
It is often necessary to encrypt data in transit between datacenters, and this encryption almost always involves public key cryptography.

However, currently used public key cipher suites, such as RSA or ECC are not quantum-safe, and it is expected that quantum computers will be able to break them in the future.

There are public key cipher suites that are quantum-safe, such as the ones based on lattice cryptography, but they are not yet widely used. Furthermore, no one can be sure that they will never be broken in the future.
So public key cryptography is not a good solution for guaranteed forward secrecy.

On the other hand, Quantum Key Distribution (QKD) is a mechanism that allows two parties to produce a shared random secret key, which can be used to encrypt and decrypt messages, and which guarantees theoretical forward secrecy.

Indeed, QKD is based on the laws of quantum physics, and it is theoretically impossible to eavesdrop on a QKD key exchange without being detected. The only condition is that the two parties have correctly authenticated each other beforehand.

### ETSI QKD standard for production environments

The [ETSI standard](docs/etsi_qkd_standard_definition.pdf) defines a protocol for usage of quantum-distributed keys by applications.

It assumes the existence of "secure-zones", meaning zones protected against cyber and physical intrusions. It is possible to assume traditional public-key cryptography is secure in these zones.
These zones can be, for example, datacenters.

On the other hand, communications between "secure-zones" as to be secured using QKD.

Standard defines the following entities:
- **Key Management Entity (KME)**: responsible for managing the keys exchanged between the secure zones and furnishing them to Secure Application Entities (SAEs).
- **Secure Application Entity (SAE)**: Exchange keys with other SAEs.

![Cross-datacenter simplified topology](assets/qkd_simple_topology.png "Cross-datacenter simplified topology").

### Software description

This software intends to manage QKD-exchanged key, in a way compliant with the ETSI standard.

This software has to be run in the KME servers. One KME can support multiple remote KMEs connections.
For compatibility purpose, it also supports key exchange between KMEs in the same zone (for which direct public-key encryption is enough).

There should exist a directory where binary key files are stored after Privacy Amplification. **These files have to be named equally on both KMEs.**

:point_right: **Note:** QKD can be performed while this software is running, it will simply detect new key files in the directory.

All the authentication is performed via SSL client and server certificates. Within the same "secure-zone", SAEs are distinguished by their client certificate serial number.

Read QKD keys are stored inside a SQL database of your choice, among [supported DBMS](#supported-dbms).

---

## Getting started

### Supported platforms

- :white_check_mark: : Guaranteed to work, as the tests are run on this platform.
- :negative_squared_cross_mark: Tested regularly, but not guaranteed to work.
- :interrobang: Should work, but not tested.

| Platform                       | Status                        |
|--------------------------------|-------------------------------|
| Linux Ubuntu 24.04 x86_64      | :white_check_mark:            |
| Windows Server 2022 x86_64     | :white_check_mark:            |
| MacOS 15 arm64                 | :white_check_mark:            |
| Windows 11 Professional x86_64 | :negative_squared_cross_mark: |
| FreeBSD 14 x86_64              | :negative_squared_cross_mark: |
| All other computer platforms   | :interrobang:                 |


**Note:** On MacOS, you need to use `pem` certificates instead of `pfx` certificates, as explained below.

If you encounter any issue on a platform, please check the [TROUBLESHOOTING.md](TROUBLESHOOTING.md) file. If you still have an issue, please open an issue on GitHub.

### Supported DBMS

- :white_check_mark: : Tested.
- :x: : Not supported.

| DBMS               | Status               | URI example                                         |
|--------------------|----------------------|-----------------------------------------------------|
| In-memory database | :white_check_mark:   | `:memory:`                                          |
| SQLite             | :white_check_mark:   | `sqlite://path/to/kme_database.db`                  |
| PostgreSQL         | :white_check_mark:   | `postgres://qkd_user:qkd_password@localhost/qkd_db` |
| MySQL/MariaDB      | :white_check_mark:   | `mysql://qkd_user:qkd_password@localhost/qkd_db`    |
| All other DBMS     | :x:                  |                                                     |

**Note**: the database or the SQLite file should already exist, but this software can create the tables if there are missing.

If you encounter any issue or want to suggest support for another DBMS, please open an issue on GitHub.

### Compilation

Install Rust programming language, as explained at https://www.rust-lang.org/tools/install.

```bash
git clone https://github.com/thomasarmel/qkd_kme_server.git
cd qkd_kme_server
cargo build --release
```

The executable will be located at `target/release/qkd_kme_server`.

### Tests:

#### Basic tests

You can run unit basic tests with:

```bash
cargo test
```

#### Persistent databases tests

To run the tests that use connection to a persistent database, follow these steps:

Install Docker following instructions at https://docs.docker.com/engine/install/

Install Docker Compose following instructions at https://docs.docker.com/compose/install/

Start the database services with Docker Compose (you may need admin privileges):
```bash
docker compose -f test_database_services_docker_compose.yml up -d
```

Wait a few seconds for the databases to be ready.

Run the tests that use persistent databases:
```bash
cargo test -- --ignored
```

When you are done, you can stop the database services with:
```bash
docker compose -f test_database_services_docker_compose.yml down
```

### Simple configuration

For a simple proof of concept in local, you can run the software with 
`config_kme1.json5` and `config_kme2.json5` files as argument for 
respectively KME1 and KME2.

For local tests, certificates are pre-generated and stored in the `certs` folder.

### Running

#### Creating local SQLite database

If you want to use a persistent SQLite database (not in-memory), you need to create an empty SQLite database file.

First install SQLite3 command line tool.

**Windows:**

```bash
winget install SQLite.SQLite
```

Then restart your terminal to have `sqlite3` command available on the system 
PATH.

**Linux:**

```bash
sudo apt install sqlite3
```

**MacOS:**

```bash
brew install sqlite
```

Then create an empty database file:

```bash
sqlite3 kme_database.db ""
```

#### QKD key directory

First of all, please ensure there is a directory in both KMEs where the QKD keys are stored.
Files should have the same name and contents in both KMEs. They should have the `.cor` extension. :red_circle: These must be the files generated **AFTER** Privacy Amplification. :red_circle:

This software will detect new files automatically in case you are doing QKD on-the-fly.

#### Generating certificates

You must generate SSL certificates for both SAE-to-KME and KME-to-KME communications (in the latter certificates are used only for authentication).

---

**Automatic certificate generation**

You can use the [qkd_kme_server_certificates_generator](https://github.com/thomasarmel/qkd_kme_server_certificates_generator) that we provide to generate all certificates automatically from a configuration file.

```bash
git clone https://github.com/thomasarmel/qkd_kme_server_certificates_generator.git
cd qkd_kme_server_certificates_generator
cargo run --release -- your_config_file.json5
```

Documentation for the configuration file is available in the [generator README](https://github.com/thomasarmel/qkd_kme_server_certificates_generator/blob/main/README.md).

---

**Manual certificate generation**

Otherwise, if you prefer to do this manually, we give below an example of how to quickly generate all SSL certificates, using `openssl`.

**KMEs' server certificates:**

For all KMEs, you can generate a self-signed certificate with:

```bash
openssl genrsa -out kme_server.key 4096
openssl req -new -key kme_server.key -out kme_server.csr
openssl x509 -req -days 3650 -in kme_server.csr -signkey kme_server.key -out kme_server.crt
```

:point_right: Add the certificate to the trusted store of the other KMEs, and trusted stires of the SAEs of the same zone.

**KMEs' CA certificates:**

For all your KMEs, you must generate two CA certificates, one for authenticating SAE-to-KME communications, and one for KME-to-KME communications.

Create a `root-ca.cnf` file containing
```
[root_ca]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical, nonRepudiation, cRLSign, keyCertSign
subjectKeyIdentifier=hash
```

Generate CA for authenticating SAEs:
```bash
openssl genrsa -out "root_ca_saes_auth.key" 4096
openssl req -new -key "root_ca_saes_auth.key" -out "root_ca_saes_auth.csr" -sha256 -subj '/CN=KME CA to authenticate its SAEs'
openssl x509 -req -days 3650 -in "root_ca_saes_auth.csr" -signkey "root_ca_saes_auth.key" -sha256 -out "root_ca_saes_auth.crt" -extfile "root-ca.cnf" -extensions root_ca
```
Generate CA for authenticating other KMEs:
```bash
openssl genrsa -out "root_ca_kmes_auth.key" 4096
openssl req -new -key "root_ca_kmes_auth.key" -out "root_ca_kmes_auth.csr" -sha256 -subj '/CN=KME CA to authenticate other KMEs'
openssl x509 -req -days 3650 -in "root_ca_kmes_auth.csr" -signkey "root_ca_kmes_auth.key" -sha256 -out "root_ca_kmes_auth.crt" -extfile "root-ca.cnf" -extensions root_ca
```

**Client certificates**

Create a `client.cnf` file containing
```
[client]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "Client Certificate to authenticate to KME server"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
```

Now you need to generate client certificates for all SAE inside the secure zone:
```bash
openssl genrsa -out "sae1_client_secure_zone.key" 4096
openssl req -new -key "sae1_client_secure_zone.key" -out "sae1_client_secure_zone.csr" -sha256 -subj '/CN=Secure zone SAE1 Client'
openssl x509 -req -days 750 -in "sae1_client_secure_zone.csr" -sha256 -CA "root_ca_saes_auth.crt" -CAkey "root_ca_saes_auth.key" -CAcreateserial -out "sae1_client_secure_zone.crt" -extfile "client.cnf" -extensions client
cat sae1_client_secure_zone.key sae1_client_secure_zone.crt root_ca_saes_auth.crt > sae1_client_secure_zone.pem
openssl pkcs12 -export -out sae1_client_secure_zone.pfx -inkey sae1_client_secure_zone.key -in sae1_client_secure_zone.pem -certfile root_ca_saes_auth.crt
```
Do the same for all the SAEs within the secure zone.

:point_right: Take note somewhere of the **serial number of the certificates**, as it will be used to identify the SAEs.

Generate client certificates for all KMEs:
```bash
openssl genrsa -out "kmeb_client_external.key" 4096
openssl req -new -key "kmeb_client_external.key" -out "kmeb_client_external.csr" -sha256 -subj '/CN=KMEb external Client from'
openssl x509 -req -days 750 -in "kmeb_client_external.csr" -sha256 -CA "root_ca_kmes_auth.crt" -CAkey "root_ca_kmes_auth.key" -CAcreateserial -out "kmeb_client_external.crt" -extfile "client.cnf" -extensions client
cat kmeb_client_external.key kmeb_client_external.crt root_ca_kmes_auth.crt > kmeb_client_external.pem
openssl pkcs12 -export -out kmeb_client_external.pfx -inkey kmeb_client_external.key -in kmeb_client_external.pem -certfile root_ca_kmes_auth.crt
```

Here is a scheme of the expected certificates for a KME:

![Expected certificates for a KME](assets/certificates_final_scheme.png "Expected certificates for a KME").

:warning: :apple: `pkcs12` format is not supported on MacOS. You should use `pem` format instead.

To convert the `.pfx` file to `.pem`, you can use the following command:

```bash
openssl pkcs12 -in certificate.pfx -clcerts -nokeys -out cert.pem
openssl pkcs12 -in certificate.pfx -nocerts -out key_enc.pem
openssl rsa -in key_enc.pem -out key.pem
cat cert.pem key.pem > test.pem
```

Enter password for the `.pfx` file when prompted. This will create a `.pem` file containing the client certificate and private key, use it in your config.

Be aware that the `.pem` file will not be encrypted, so make sure to set the correct permissions on it.

Then replace the `other_kmes/https_client_authentication_certificate` field in your config with the path to the `.pem` file you just created. You can set an empty password for the `other_kmes/https_client_authentication_certificate_password` field.

#### Starting the server

```bash
target/release/qkd_kme_server kme_config.json5
```
with `kme_config.json5` being the configuration file for the KME, explained 
below.

Wait a few seconds until all keys are loaded and the server is ready.

Launch the server on all KMEs.

:warning: There can be an error in case OpenSSL version you used to generate the certificates is outdated.

---

## Configuration

The whole configuration is stored in a JSON5 file. You can find examples in 
`config_kme1.json5` and `config_kme2.json5`.

The detailled configuration options are explained in [docs/config.md](docs/config.md).

---


## Routes

Routes implemented by our implementation, both official and implementation-specific, are explained in detail in [docs/api.md](docs/api.md).

---

## HTTP debugging interface

As explained above, you can access a web interface using your web browser to consult the KME status and logs if you set it in configuration.

Events displayed look like:

```
2024-02-26T08:53:16.847785700Z: [Bob] Key de4f4010-ed34-2d51-ab3c-63240a8df9e1 activated between SAEs 1 and 2

2024-02-26T08:53:16.879269100Z: [Bob] SAE 2 requested key de4f4010-ed34-2d51-ab3c-63240a8df9e1 (from 1)

2024-02-26T08:55:11.036073500Z: [Bob] Key 4985cdbb-35ed-d555-9030-b171773d6483 activated between SAEs 1 and 2

2024-02-26T08:55:11.061108300Z: [Bob] SAE 2 requested key 4985cdbb-35ed-d555-9030-b171773d6483 (from 1)

2024-02-26T08:56:01.653345800Z: [Bob] SAE 2 requested a key to communicate with 1

2024-02-26T08:56:01.690181100Z: [Bob] As SAE 1 belongs to KME 1, activating it through inter KMEs network

2024-02-26T08:56:01.690332800Z: [Bob] Key b7a86bdd-c342-5b5f-b10c-c957cb1d8e75 activated between SAEs 2 and 1
```

# Building portable binaries

You may want to build portable binaries that can be launch directly on 
another machine without any further configuration or installation. So that 
your binary can be launched by non-specialists.

## Windows:

On Windows, `cargo build --release` already produces portable binary that 
is only linked to DLL files that are present by default on Windows:

![Dependency walker output for Windows binary](assets/dependencies_dll_windows.png)

## Linux:

On Linux, by default `cargo build --release` produces a binary that is linked
to shared libraries that may not be present on the target machine, like `libc.so`:

![ldd for dynamically linked Linux binary](assets/compile_dynamic_linux.png)

The solution is to build a static binary, linked to `musl` instead of `glibc`:

```bash
sudo apt-get update && sudo apt-get install musl-tools
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl
```

![ldd for statically linked Linux binary](assets/compile_static_linux.png)

(If issues arise during compilation, please check the [TROUBLESHOOTING.md](TROUBLESHOOTING.md) file)

# Troubleshooting

Please check the file [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues / FAQ.

# Contributing

All contributions are welcome! Please check the [CONTRIBUTING.md](CONTRIBUTING.md) file for more information.

# Citation

Prévost, T., Martin, B. and Alibart, O. (2025). An ETSI GS QKD Compliant TLS Implementation. In Proceedings of the 22nd International Conference on Security and Cryptography - SECRYPT; ISBN 978-989-758-760-3; ISSN 2184-7711, SciTePress, pages 705-710. DOI: 10.5220/0013564700003979

### Bibtex entry:
```
@conference{secrypt25,
author={Thomas Prévost and Bruno Martin and Olivier Alibart},
title={An ETSI GS QKD Compliant TLS Implementation},
booktitle={Proceedings of the 22nd International Conference on Security and Cryptography - SECRYPT},
year={2025},
pages={705-710},
publisher={SciTePress},
organization={INSTICC},
doi={10.5220/0013564700003979},
isbn={978-989-758-760-3},
issn={2184-7711},
}

```


# Related resources

This Cloud service will allow you to test the ETSI GS QKD API: https://qukaydee.com/pages/about
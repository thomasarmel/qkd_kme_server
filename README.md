# ETSI QKD KME server implementation

*The following repository contains an implementation proposal for the KME (Key Management Entity) server defined in the [ETSI QKD standard](docs/etsi_qkd_standard_definition.pdf).*

---

## Installation

### Compilation

Install Rust programming language, as explained at https://www.rust-lang.org/tools/install.

```bash
git clone https://github.com/thomasarmel/qkd_kme_server.git
cd qkd_kme_server
cargo build --release
```

### Certificate installation

I already generated some certificates for your tests, but you can obviously generate your own ones.

Simply put [certs/CA-zone1.crt](certs/CA-zone1.crt) into your trusted CA certificates folder and [certs/sae1.pfx](certs/sae1.pfx) into your client certificates store.
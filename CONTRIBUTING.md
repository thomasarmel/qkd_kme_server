# Contributing

Thank you for your interest in contributing to this project! We welcome contributions from everyone. Please follow the guidelines below to ensure a smooth process.

---

## General philosophy of the project

This project aims to facilitate the creation of new products based on Quantum Key Distribution (QKD), compatible 
with the [ETSI GS QKD 014 standard](docs/etsi_qkd_standard_definition.pdf).

### Accessibility

The program must be easily launched by people with little DevOps knowledge. Contributions requiring the code to run 
on Docker, Kubernetes, etc., will be rejected. However, the contributions should facilitate integration with these 
DevOps tools. The same goes for databases: while we encourage contributors 
to facilitate integration with as many DBMSs as possible, it must be possible to run the program with a simple SQLite database, on a disk file, or in memory (`:memory:`). 

The program must be able to be launched with a few command lines from 
[officially supported platforms](README.md#supported-platforms). A non-expert must be able to launch the 
project with just a few command lines (`git clone`, `cd`, `cargo run 
--release`). The code must run on operating system versions still supported 
by the publisher (no need to support Windows XP, for example). It is assumed that the user is using the latest version of the compiler.

### Contributions addressing a specific need

Contributions addressing a specific need other than compliance with the ETSI 
GS QKD 014 standard are **accepted** (e.g., displaying the entropy of 
generated keys). However, such contributions must not break the API or the 
program's functionality. These additions must be documented in the README.

If you cannot address your specific need without breaking the API, create a separate GitHub repository; the maintainers can link to your project in the README.

---

## Coding guidelines

The code must remain readable and well-documented. All changes must be unit tested. Any changes impacting the API's functionality must also be integration tested and possibly documented in the README.

Removing compiler directives (such as `#![forbid(unsafe_code)]` or `#![deny
(missing_docs)]`) to validate a pull request is prohibited. Removing targets 
in the GitHub actions workflow is also prohibited: the code must compile and work on all [officially supported platforms](README.md#supported-platforms).

### Adding New Dependencies

It's best to limit the addition of new dependencies. However, if your 
contribution absolutely requires new dependencies, then we recommend using 
**pure-rust crates**, which are more likely to compile the first time on a 
different machine. It will also be easier to offer a static binary, without dependency on shared libraries.

---

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.
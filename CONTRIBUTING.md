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

### Our Pledge

In the interest of fostering an open and welcoming environment, we as contributors and maintainers pledge to making 
participation in our project and our community a harassment-free experience for everyone, regardless of age, body 
size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.  

### Our Standards

Examples of behavior that contributes to creating a positive environment include:

* Using welcoming and inclusive language
* Being respectful of differing viewpoints and experiences
* Gracefully accepting constructive criticism
* Focusing on what is best for the community
* Showing empathy towards other community members

Examples of unacceptable behavior by participants include:

* The use of sexualized language or imagery and unwelcome sexual attention or
  advances
* Trolling, insulting/derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information, such as a physical or electronic
  address, without explicit permission
* Other conduct which could reasonably be considered inappropriate in a
  professional setting

### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable
behavior and are expected to take appropriate and fair corrective action in
response to any instances of unacceptable behavior.

Project maintainers have the right and responsibility to remove, edit, or
reject comments, commits, code, wiki edits, issues, and other contributions
that are not aligned to this Code of Conduct, or to ban temporarily or
permanently any contributor for other behaviors that they deem inappropriate,
threatening, offensive, or harmful.

### Scope

This Code of Conduct applies both within project spaces and in public spaces
when an individual is representing the project or its community. Examples of
representing a project or community include using an official project e-mail
address, posting via an official social media account, or acting as an appointed
representative at an online or offline event. Representation of a project may be
further defined and clarified by project maintainers.

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported by contacting the project team at **thomas.prevost \[at\] univ-cotedazur.fr**. All
complaints will be reviewed and investigated and will result in a response that
is deemed necessary and appropriate to the circumstances. The project team is
obligated to maintain confidentiality with regard to the reporter of an incident.
Further details of specific enforcement policies may be posted separately.

Project maintainers who do not follow or enforce the Code of Conduct in good
faith may face temporary or permanent repercussions as determined by other
members of the project's leadership.

_This Code of Conduct is adapted from the [Contributor Covenant][homepage], version 1.4, available at [http://contributor-covenant.org/version/1/4][version]_

[homepage]: http://contributor-covenant.org
[version]: http://contributor-covenant.org/version/1/4/
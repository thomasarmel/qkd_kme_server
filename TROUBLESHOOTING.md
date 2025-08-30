# Troubleshooting / FAQ

_Common issues and their solutions._

---

## On Windows: `failed to run custom build command for aws-lc-sys v...`

### Solution: Install `nasm` and `cmake`

Install [nasm](https://www.nasm.us/pub/nasm/releasebuilds/) and [cmake](https://cmake.org/download/), add their install directories to your `PATH` environment variable, and restart your terminal.


---

## On Linux: `failed to run custom build command for 'openssl-sys v...` 

And if you scroll down, you see: `Could not find openssl via pkg-config`.

### Solution: Install OpenSSL development package

On Debian / Ubuntu, run:

```bash
sudo apt install libssl-dev
```

On CentOS / RHEL, run:

```bash
sudo yum install openssl-devel
```
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

## On Linux: `aws-lc-sys-0.32.0/aws-lc/crypto/rand_extra/urandom.c:39:10: fatal error: linux/random.h: No such file or directory`

This could happen if you compile a static binary using musl (`--target=x86_64-unknown-linux-musl`).

It's a known issue: https://github.com/aws/aws-lc-rs/issues/894

### Solution: install `linux-libc-dev`:
On Debian / Ubuntu, run:

```bash
sudo apt install linux-libc-dev
```

Add a symbolic link to `asm` include directory: for x86_64:

```bash
sudo ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```

Or for ARM64:

```bash
sudo ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/asm
```

Then compile with env variable **C_INCLUDE_PATH**="/usr/include":

```bash
C_INCLUDE_PATH="/usr/include" cargo build --target=x86_64-unknown-linux-musl
```
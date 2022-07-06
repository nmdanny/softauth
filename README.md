# Introduction

This is a WIP software implementation of a Webauthn authenticator based on 
emulating a roaming authenticator using the FIDO CTAP2 protocol, using the Linux userspace HID subsystem.

# Running

Clone this repository and run

```shell
cargo run && sudo -E target/debug/softauth
```

Sudo permissions are required to run the authenticator due to interaction with the uHID subsystem.

# Testing


```shell
cargo test
```
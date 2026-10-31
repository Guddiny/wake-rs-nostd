![alt text](image.png)

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
# wake-rs-nostd
Implementation of `Wake` protocol for no_std.

Read more about `Wake`: http://www.leoniv.diod.club/articles/wake/wake.html 

# Implementation
This implementation is inspired by https://github.com/ew1abz/wake-rs. 
It use [heapless](https://docs.rs/heapless/latest/heapless/) crate to avoid heap allocations.

# Usage

### Add to cargo.toml
```toml
wake = { git = "https://github.com/Guddiny/wake-rs-nostd", branch = "main" }
```
To support `defmt`
```toml
wake = { ..., features = ["defmt"] }
```

### Code example
```Rust
let pkg = Packet {
    address: Some(0x11),
    command: 0xC1,
    data: Some(Vec::from_slice(&[0x11, 0x22, 0x22]).unwrap())
};
let encoded = pkg.encode().unwrap();
let decoded = encoded.decode().unwrap();
```
# RustyPod
A rewrite of iPod OS in Rust

![transpilation progress](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fgabrielchantayan%2Frustypod%2Fbadges%2Fprogress.json)

---

For funsies, this is a rewrite of a decompiled version of iPod OS 35.2.0.4 in Rust.

Later will be adding some new features and refreshing the look.

But for the time being, Kimi K3 is ripping away at rewriting. Godspeed Kimi. Godspeed.

---

## What this is

An incremental Rust port of iPod Classic 6G (S5L8702, ARMv5TE) retailOS,
function by function, verified against the original machine code. The
decompilation/decryption pipeline lives in the sibling repo
[`../ipod-decomp`](../ipod-decomp); this crate is the Rust output.

- `src/` — ported functions (one module per function family)
- `names.yaml` — knowledge base: osos addresses → semantic names/signatures
- `PORTING.md` — how to port the next function
- 14 ARM ADS runtime functions ported so far (memmove, memcpy, memzero,
  memset, memcmp, memchr, strcpy, strncpy, strncmp, strcat, strncat,
  strchr, strrchr, strstr, __rt_uread4/__rt_uwrite4, strlen_safe)

## Build & test

```sh
cargo test --target aarch64-apple-darwin        # host behavioral tests
PATH="$HOME/.cargo/bin:$PATH" \
  cargo build -Z build-std=core --release       # ARM staticlib (nightly)
```

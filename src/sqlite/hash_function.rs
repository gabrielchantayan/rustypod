//! Selecting the key hash for SQLite's generic hash tables — the tiny
//! `hashFunction` dispatcher of hash.c.
//!
//! - `hash_function` — original: `FUN_082d2a1c` @ 0x082d2a1c (16
//!   bytes, plus an 8-byte literal pool at 0x082d2a2c/0x082d2a30; 3
//!   `bl` call sites). SQLite 3.4.x/3.5.x's `hashFunction`:
//!
//! ```c
//! static int (*hashFunction(int keyClass))(const void*,int){
//!   if( keyClass==SQLITE_HASH_STRING ){
//!     return &strHash;
//!   }else{
//!     assert( keyClass==SQLITE_HASH_BINARY );
//!     return &binHash;
//!   }
//! }
//! ```
//!
//! The whole body is a two-way constant select (the assert is compiled
//! out — NDEBUG):
//!
//! ```text
//! 082d2a1c:  cmp    r0,#0x3          ; SQLITE_HASH_STRING
//! 082d2a20:  ldrne  r0,[0x82d2a2c]   ; -> binHash @ runtime 0x082ac9b4
//! 082d2a24:  ldreq  r0,[0x82d2a30]   ; -> strHash @ runtime 0x08386f14
//! 082d2a28:  bx     lr
//! ```
//!
//! The key-class numbering comes from this build's hash.h:
//! `SQLITE_HASH_INT` (1) and `SQLITE_HASH_POINTER` (2) are compiled
//! out (`#if 0 /* NOT USED */` in hash.c's hashFunction — which is why
//! this is a two-way select, not a four-way switch), leaving
//! `SQLITE_HASH_STRING` = 3 and `SQLITE_HASH_BINARY` = 4.
//!
//! Callers (all three load `keyClass` from `Hash + 0x00` with an
//! `ldrb`, then `blx` the returned pointer with `(pKey, nKey)` and mask
//! the result with `htsize - 1`):
//!
//! - `rehash` @ 0x0836741c (`bl` @ 0x08367470),
//! - `sqlite3HashFind` @ 0x0837ad88 (`bl` @ 0x0837adac),
//! - `sqlite3HashInsert` @ 0x0837ae08 (`bl` @ 0x0837ae20).
//!
//! The two targets, and where their code actually lives in the image
//! (the +0xaed8 runtime/image skew documented in [`super`]):
//!
//! - `strHash` — runtime 0x08386f14, image 0x08391dec: the
//!   case-insensitive string hash (`h = fold(c) ^ h ^ (h << 3)` per
//!   byte through `sqlite3UpperToLower`, with a strlen probe for
//!   `nKey <= 0`). Already ported as
//!   [`super::strhash::string_hash_tabled`] — this dispatcher is the
//!   "function pointer in SQLite's Hash machinery" that module's
//!   scouting note predicted.
//! - `binHash` — runtime 0x082ac9b4, image 0x082b788c: the raw binary
//!   hash (`h = byte ^ h ^ (h << 3)` per byte, no case fold, no
//!   strlen probe — `nKey <= 0` hashes nothing). It sits in a
//!   Ghidra-undecoded data gap; the 36 bytes decode by hand to
//!   `mov r2,#0 / subs r3,r1,#0 / ldrbgt r3,[r0],#1 / eorgt r2,r2,r2,
//!   lsl #3 / sub r1,r1,#1 / eorgt r2,r3,r2 / bgt ... / bic r0,r2,
//!   #0x80000000 / bx lr`. Identified, not yet ported.
//!
//! Deviation: none in behavior, but note the port returns the stock
//! runtime addresses exactly as the original's literal pool does —
//! not the addresses of the Rust ports. That keeps the dispatcher
//! transparent to hooks planted on either hash's stock address (this
//! is how the already-ported `strHash` reaches its callers).

/// A key hash in SQLite's `Hash` machinery: hashes `key_len` bytes at
/// `key` and returns `h & 0x7fffffff`. The original C type is
/// `int (*)(const void *, int)`; the pointer shape matches the ported
/// [`super::strhash::string_hash_tabled`].
pub type HashFn = unsafe extern "C" fn(key: *const u8, key_len: i32) -> u32;

/// `SQLITE_HASH_STRING` from this build's hash.h: case-insensitive
/// string keys (`SQLITE_HASH_INT` = 1 and `SQLITE_HASH_POINTER` = 2
/// exist in the enum but are compiled out of `hashFunction`).
pub const SQLITE_HASH_STRING: i32 = 3;

/// `SQLITE_HASH_BINARY` from this build's hash.h: raw binary keys.
pub const SQLITE_HASH_BINARY: i32 = 4;

/// Runtime address of `strHash` (image 0x08391dec under the +0xaed8
/// skew — see [`super`]); ported as
/// [`super::strhash::string_hash_tabled`]. This is the word stored in
/// the original's literal pool at 0x082d2a30.
pub const STR_HASH_ADDR: usize = 0x0838_6f14;

/// Runtime address of `binHash` (image 0x082b788c, in a
/// Ghidra-undecoded gap; identified, not yet ported). This is the word
/// stored in the original's literal pool at 0x082d2a2c.
pub const BIN_HASH_ADDR: usize = 0x082a_c9b4;

/// hash_function — original: `FUN_082d2a1c` @ 0x082d2a1c (16 bytes).
///
/// `hashFunction`: returns the address of the case-insensitive string
/// hash (`strHash`) when `key_class` is [`SQLITE_HASH_STRING`], and of
/// the raw binary hash (`binHash`) for every other class — in practice
/// [`SQLITE_HASH_BINARY`], the only other live class.
///
/// The returned pointer names firmware code and is only callable
/// on-target; host tests compare addresses.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn hash_function(key_class: i32) -> HashFn {
    let mut target = BIN_HASH_ADDR;
    if key_class == SQLITE_HASH_STRING {
        target = STR_HASH_ADDR;
    }
    // SAFETY: both constants name firmware entry points with the
    // `int (const void *, int)` signature; the pointer is only ever
    // called on-target (or through a hook planted at that address).
    unsafe { core::mem::transmute::<usize, HashFn>(target) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two words of the original's literal pool, read from the
    /// image at 0x082d2a2c / 0x082d2a30 (load addresses — the pool
    /// itself is below the skewed region).
    const POOL_BIN: usize = 0x082a_c9b4;
    const POOL_STR: usize = 0x0838_6f14;

    #[test]
    fn the_pool_constants_match_the_image() {
        assert_eq!(BIN_HASH_ADDR, POOL_BIN, "word @ 0x082d2a2c");
        assert_eq!(STR_HASH_ADDR, POOL_STR, "word @ 0x082d2a30");
    }

    #[test]
    fn string_keys_select_the_case_insensitive_hash() {
        assert_eq!(hash_function(SQLITE_HASH_STRING) as usize, STR_HASH_ADDR);
    }

    #[test]
    fn binary_keys_select_the_raw_hash() {
        assert_eq!(hash_function(SQLITE_HASH_BINARY) as usize, BIN_HASH_ADDR);
    }

    #[test]
    fn every_other_class_takes_the_binary_branch() {
        // The original is a single `cmp #3` with an ldrne default —
        // no range check on either side (the compiled-out classes 1/2
        // and any garbage land on binHash too).
        for class in [i32::MIN, -1, 0, 1, 2, 5, 6, 100, i32::MAX] {
            assert_eq!(
                hash_function(class) as usize,
                BIN_HASH_ADDR,
                "class {class} must fall through to binHash"
            );
        }
    }
}

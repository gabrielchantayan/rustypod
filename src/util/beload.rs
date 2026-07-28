//! Alignment-free big-endian 32-bit accessors.
//!
//! - `load_be32` — originals: `FUN_081f3b30` @ 0x081f3b30 (36 bytes;
//!   4 call sites, binary-scanned, all in the format-header parser
//!   cluster immediately after it @ 0x081f3b54..0x081f3c80) **and**
//!   `FUN_0837a158` @ 0x0837a158 (36 bytes; 59 `bl` call sites), which
//!   is SQLite's `sqlite3Get4byte` — the b-tree page-header reader.
//!   The two are byte-identical: all 36 bytes at both addresses match
//!   exactly, so they are one function the linker emitted twice (once
//!   into the media-format parser's unit, once into SQLite's). One Rust
//!   symbol serves both; both addresses hook it.
//! - `store_be32` — original: `FUN_083816cc` @ 0x083816cc (32 bytes;
//!   38 `bl` call sites). SQLite's `sqlite3Put4byte`, the write twin of
//!   the above: four `strb`s, most significant byte first.
//!
//! Algorithm: assemble/split a 32-bit value big-endian through
//! individual byte accesses (`ldrb`/`strb`), so the pointer needs no
//! alignment. Unlike the `berec_*` family @ 0x0813b714 (which reads
//! through a buffer handle), these take the byte pointer directly.

/// Big-endian, alignment-free 32-bit load from `p`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn load_be32(p: *const u8) -> u32 {
    (p.read() as u32) << 24
        | (p.add(1).read() as u32) << 16
        | (p.add(2).read() as u32) << 8
        | p.add(3).read() as u32
}

/// store_be32 — original: `FUN_083816cc` @ 0x083816cc (32 bytes;
/// 38 `bl` call sites).
///
/// Big-endian, alignment-free 32-bit store of `value` at `p`. Writes
/// exactly four bytes and nothing else.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn store_be32(p: *mut u8, value: u32) {
    p.write((value >> 24) as u8);
    p.add(1).write((value >> 16) as u8);
    p.add(2).write((value >> 8) as u8);
    p.add(3).write(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_big_endian() {
        let buf = [0xdeu8, 0xad, 0xbe, 0xef];
        assert_eq!(unsafe { load_be32(buf.as_ptr()) }, 0xdead_beef);
    }

    #[test]
    fn works_at_every_misalignment() {
        let buf: [u8; 12] = core::array::from_fn(|i| i as u8 + 1);
        for off in 0..8 {
            let expect = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            assert_eq!(unsafe { load_be32(buf.as_ptr().add(off)) }, expect, "off={off}");
        }
    }

    #[test]
    fn edge_patterns() {
        assert_eq!(unsafe { load_be32([0, 0, 0, 0].as_ptr()) }, 0);
        assert_eq!(unsafe { load_be32([0xff, 0xff, 0xff, 0xff].as_ptr()) }, u32::MAX);
        assert_eq!(unsafe { load_be32([0x80, 0, 0, 1].as_ptr()) }, 0x8000_0001);
        assert_eq!(unsafe { load_be32([0, 0, 0, 1].as_ptr()) }, 1);
    }

    #[test]
    fn store_splits_big_endian() {
        let mut buf = [0u8; 4];
        unsafe { store_be32(buf.as_mut_ptr(), 0xdead_beef) };
        assert_eq!(buf, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn store_round_trips_through_load_at_every_misalignment() {
        for value in [0u32, 1, 0xff, 0x0100, 0x8000_0000, 0x1234_5678, u32::MAX] {
            for off in 0..8usize {
                let mut buf = [0xa5u8; 16];
                unsafe { store_be32(buf.as_mut_ptr().add(off), value) };
                assert_eq!(unsafe { load_be32(buf.as_ptr().add(off)) }, value);
                // Exactly four bytes moved.
                for (i, byte) in buf.iter().enumerate() {
                    if !(off..off + 4).contains(&i) {
                        assert_eq!(*byte, 0xa5, "value {value:#x} off {off} byte {i}");
                    }
                }
            }
        }
    }

    #[test]
    fn store_writes_the_most_significant_byte_first() {
        let mut buf = [0u8; 4];
        unsafe { store_be32(buf.as_mut_ptr(), 0x0102_0304) };
        assert_eq!(buf, [1, 2, 3, 4]);
        unsafe { store_be32(buf.as_mut_ptr(), 0) };
        assert_eq!(buf, [0, 0, 0, 0]);
    }
}

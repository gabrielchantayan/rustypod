//! load_be32 — original: `FUN_081f3b30` @ 0x081f3b30 (36 bytes; 4 call
//! sites, binary-scanned, all in the format-header parser cluster
//! immediately after it @ 0x081f3b54..0x081f3c80).
//!
//! Algorithm: assemble a 32-bit value big-endian from 4 individual byte
//! loads (`ldrb`), so the pointer needs no alignment. Unlike the
//! `berec_*` family @ 0x0813b714 (which reads through a buffer handle),
//! this one takes the byte pointer directly.

/// Big-endian, alignment-free 32-bit load from `p`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn load_be32(p: *const u8) -> u32 {
    (p.read() as u32) << 24
        | (p.add(1).read() as u32) << 16
        | (p.add(2).read() as u32) << 8
        | p.add(3).read() as u32
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
}

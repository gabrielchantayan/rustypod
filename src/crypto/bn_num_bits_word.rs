//! OpenSSL's `BN_num_bits_word` — the limb bit-length helper of the
//! `BIGNUM` type in the OpenSSL copy Apple vendored into retailOS
//! (the SSLeay-era libcrypto whose BN layer is documented in this
//! module's siblings, see crypto/bn_num_bits.rs).
//!
//! Port: `bn_num_bits_word` — `FUN_080404dc` @ 0x080404dc (56 bytes,
//! 0x080404dc..0x08040514 plus one literal-pool word @ 0x08040514;
//! the next entry @ 0x08040518 is a separately linked function with
//! its own callers, so Ghidra's 56-byte extent is exactly right;
//! **5 call sites**, binary-verified by decoding every ARM B/BL word
//! in osos.dec: all 5 are unconditional `bl` — no predicated forms,
//! no tail branches, so no caller gates the call).
//!
//! # Decoded from the raw ARM at 0x080404dc
//!
//! ```text
//! ldr    r1, [0x8040514]      ; r1 = 0x08906520, the bits[256] table base
//! movs   r2, r0, lsr #16      ; high half nonzero?
//! beq    0x08040500           ;   no -> low-half path
//! tst    r0, #0xff000000      ; byte 3 nonzero?
//! ldrbeq r0, [r1, r0, lsr #16];   no -> bits[byte 2]
//! addeq  r0, r0, #16
//! ldrbne r0, [r1, r0, lsr #24];   yes -> bits[byte 3]
//! addne  r0, r0, #24
//! bx     lr
//! 08040500:
//! tst    r0, #0xff00          ; byte 1 nonzero?
//! ldrbeq r0, [r1, r0]         ;   no -> bits[byte 0] (limb < 256, incl. 0)
//! ldrbne r0, [r1, r0, lsr #8] ;   yes -> bits[byte 1]
//! addne  r0, r0, #8
//! bx     lr
//! ```
//!
//! Upstream crypto/bn/bn_lib.c:
//! `int BN_num_bits_word(BN_ULONG l) { ... if (l & 0xffff0000L)
//! return (bits[(l >> shift)] + shift) ... }` — select the most
//! significant nonzero byte of the limb, return `bits[byte] + 8*k`
//! (k = byte index 0..3); a zero limb returns `bits[0]`. Upstream
//! `bits[b] = floor(log2(b)) + 1` (bit length of the byte,
//! `bits[0] = 0`), so the helper yields the limb's bit length
//! 1..=32 and 0 for a zero limb — consistent with `BN_num_bits`'s
//! RSA-1024 `== 0x400` caller @ 0x082d48ac (top limb bit length 32
//! over 32 limbs gives 31*32 + 32 = 1024) and with `bits[0] = 0`
//! making a zero top limb contribute nothing.
//!
//! # The bits[] table anomaly
//!
//! The literal pool word @ 0x08040514 is 0x08906520, which at rest
//! lands in the middle of the Italian UI string heap (`"tata.\0"`
//! inside `"...non è più supportata."`). No instruction writes a
//! table there and no canonical `{0,1,2,2,3,3,3,3,...}` byte run
//! exists anywhere in osos.dec, so the runtime content of
//! 0x08906520 must be installed by a loader pass this port does not
//! model — documented, not explained, in crypto/bn_num_bits.rs.
//! Whatever installs it must install the canonical upstream table
//! (the RSA-1024 modulus check fails otherwise), so this port bakes
//! the upstream `bits[256]` in as a `const` table instead of
//! dereferencing 0x08906520; behavior is identical once the loader
//! pass has run.
//!
//! # Deviations
//!
//! - The table is a compiled-in `const [u8; 256]` (upstream's
//!   `static const unsigned char bits[256]`) rather than the runtime
//!   0x08906520 pointer the literal pool names; see the anomaly
//!   above. Reads go through `read_volatile` so LLVM cannot prove
//!   the table constant and collapse the byte-select tree into a
//!   `clz` — the original has no CLZ-class instruction.
//! - Upstream computes the byte index with `shift` loop bookkeeping;
//!   the firmware's compiled form is the branch tree below, and the
//!   port mirrors that tree one-to-one.

/// Upstream `static const unsigned char bits[256]`:
/// `bits[b] = floor(log2(b)) + 1`, `bits[0] = 0` — the bit length
/// of a byte.
const BITS: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut b = 1usize;
    while b < 256 {
        // floor(log2(b)) + 1: count bits without leading_zeros (const).
        let mut v = b;
        let mut n = 0u8;
        while v != 0 {
            n += 1;
            v >>= 1;
        }
        t[b] = n;
        b += 1;
    }
    t
};

/// Volatile table read: keeps LLVM from folding the lookup against
/// the known-constant table and replacing the whole byte-select tree
/// with a `clz` (the original is a branch tree around `ldrb`, not a
/// count-leading-zeros).
#[inline(always)]
fn bits(idx: u32) -> i32 {
    (unsafe { core::ptr::read_volatile(BITS.as_ptr().add(idx as usize)) }) as i32
}

/// bn_num_bits_word — original: `FUN_080404dc` @ 0x080404dc (56
/// bytes; 5 call sites, all unconditional `bl` — binary-verified).
///
/// OpenSSL `BN_num_bits_word`: the bit length of one limb —
/// `bits[most significant nonzero byte] + 8 * (byte index)`, 0 for a
/// zero limb (`bits[0] = 0`).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_num_bits_word(limb: u32) -> i32 {
    if limb >> 16 != 0 {
        if limb & 0xff00_0000 != 0 {
            bits(limb >> 24) + 24
        } else {
            bits(limb >> 16) + 16
        }
    } else if limb & 0xff00 != 0 {
        bits(limb >> 8) + 8
    } else {
        bits(limb)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    /// Reference: the bit length of the value.
    fn reference(limb: u32) -> i32 {
        if limb == 0 {
            0
        } else {
            (32 - limb.leading_zeros()) as i32
        }
    }

    #[test]
    fn zero_limb_is_zero_bits() {
        assert_eq!(unsafe { bn_num_bits_word(0) }, 0);
    }

    #[test]
    fn each_byte_index_selects_its_lane() {
        // Same byte (0x80, bits = 8) in each lane: the +8*k term must
        // track the byte index, mirroring the firmware's branch tree.
        assert_eq!(unsafe { bn_num_bits_word(0x0000_0080) }, 8);
        assert_eq!(unsafe { bn_num_bits_word(0x0000_8000) }, 16);
        assert_eq!(unsafe { bn_num_bits_word(0x0080_0000) }, 24);
        assert_eq!(unsafe { bn_num_bits_word(0x8000_0000) }, 32);
        // Lower bytes below the most significant one are ignored.
        assert_eq!(unsafe { bn_num_bits_word(0x00ff_ffff) }, 24);
        assert_eq!(unsafe { bn_num_bits_word(0x0001_0000) }, 17);
        assert_eq!(unsafe { bn_num_bits_word(0x0000_0100) }, 9);
        assert_eq!(unsafe { bn_num_bits_word(0x0000_0001) }, 1);
    }

    #[test]
    fn matches_reference_exhaustively_over_byte_edges() {
        // Every byte value in every lane, with the lower lanes filled
        // with 0x00/0xff noise, plus the power-of-two boundaries.
        let mut cases: Vec<u32> = Vec::new();
        for lane in 0..4u32 {
            for byte in 0..256u32 {
                for low in [0u32, 0xffff_ffff] {
                    let high = byte << (8 * lane);
                    cases.push(high | (low & ((1u32 << (8 * lane)).wrapping_sub(1))));
                }
            }
        }
        for shift in 0..32u32 {
            cases.push(1u32 << shift);
            cases.push((1u32 << shift) - 1);
        }
        cases.push(u32::MAX);
        for limb in cases {
            assert_eq!(
                unsafe { bn_num_bits_word(limb) },
                reference(limb),
                "limb {limb:#010x}"
            );
        }
    }
}

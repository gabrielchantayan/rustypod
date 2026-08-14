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
//! - `store_u32_be_bytes` — original: `FUN_08046b1c` @ 0x08046b1c
//!   (40 bytes; 3 recovered decompiler call sites). A separate
//!   big-endian byte-store implementation: it spills `value` then copies
//!   its bytes from most to least significant, so it remains a distinct
//!   firmware function rather than an alias of `store_be32`.
//!
//! Algorithm: assemble/split a 32-bit value big-endian through
//! individual byte accesses (`ldrb`/`strb`), so the pointer needs no
//! alignment. Unlike the `berec_*` family @ 0x0813b714 (which reads
//! through a buffer handle), these take the byte pointer directly.
//!
//! The wire-format overload set @ 0x0826161c..0x082617ec — `pack_be16`,
//! `pack_be32`, `pack_be64`, `unpack_be16`, `unpack_be32`, `unpack_be64`
//! and the two register-only byte reversers they share — lives at the
//! bottom of this file; see the banner there.

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

/// store_u32_be_bytes — original: `FUN_08046b1c` @ 0x08046b1c (40 bytes;
/// 3 recovered decompiler call sites).
///
/// Stores the logical `u32` value as four big-endian bytes at `p`: bits
/// 31..24 through 7..0 go to increasing byte addresses. The original spills
/// the little-endian ARM argument then loads offsets 3, 2, 1, 0 with `ldrb`
/// before four `strb`s; these shifts express the same byte order directly.
/// It accepts any valid writable four-byte range, including unaligned ones.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.store_u32_be_bytes")]
pub unsafe extern "C" fn store_u32_be_bytes(p: *mut u8, value: u32) {
    p.write((value >> 24) as u8);
    p.add(1).write((value >> 16) as u8);
    p.add(2).write((value >> 8) as u8);
    p.add(3).write(value as u8);
}

// ---------------------------------------------------------------------------
// The wire-format packer cluster @ 0x0826161c..0x082617ec.
//
// A contiguous overload set in the C++ framework layer, one entry per width
// and direction, sharing the same shape: pack = byte-reverse the value then
// spill its bytes to ascending addresses; unpack = gather ascending bytes
// into a little-endian word then byte-reverse it. Binary-verified extents
// (words decoded from osos.dec, not Ghidra):
//
//   0x0826161c  16-bit pack      0x08261750  16-bit unpack
//   0x08261638  32-bit pack      0x08261770  32-bit unpack
//   0x08261670  64-bit pack      0x08261790  64-bit unpack
//
// Two register-only byte reversers sit between the two halves and are shared
// by both: `reverse_bytes32` @ 0x082616d4 and `reverse_bytes64` @ 0x082616f0.
// The 32- and 64-bit unpacks reach theirs by tail branch (`b`, not `bl`); the
// 64-bit pack calls its one with a real `bl`. Both are reached by direct `bl`
// from elsewhere too, so both are genuine firmware entry points, not inlining
// artefacts.
//
// Every function here is exported into its own text section: their bodies are
// near-identical and LLVM would otherwise fold several onto a single symbol,
// leaving the rest of the family with no address to hook.
//
// Callers identify the domain: every recovered one builds or parses a
// packet in a small stack/record buffer with a running byte-length cursor
// (e.g. FUN_081ac6f0 @ 0x081ac7bc fills a six-byte reply body then hands it
// to the transport @ 0x080f6efc; FUN_081fffac @ 0x08200044 appends four
// bytes at `packet + packet[6] + 7` and then bumps `packet[6]` by 4). Hence
// pack/unpack rather than store/load: these serve a big-endian wire format,
// not in-memory structures.
//
// Ghidra sizes both functions wrong in opposite directions to the usual: it
// reports 60 bytes for 0x08261770, which runs 0x2c bytes past the tail
// branch at 0x0826178c and swallows the separately-linked 64-bit unpack
// that starts at 0x08261790.
// ---------------------------------------------------------------------------

/// pack_be16 — original: `FUN_0826161c` @ 0x0826161c (28 bytes, all code:
/// 6 instructions plus `bx lr`; 46 `bl` call sites, counted by decoding
/// every B/BL word in osos.dec).
///
/// Writes `value` as two big-endian bytes at `dst`, needing no alignment.
///
/// The first member of the overload set, and the same two-step shape as
/// [`pack_be32`]: reverse the halfword in registers (`lsl #8`, then `orr`
/// of `value & 0xff00` shifted right 8), then spill its two bytes
/// least-significant first to ascending addresses. The original ignores
/// the argument register's top half, which the `u16` parameter states
/// directly. Its own text section keeps it off the other packers' symbols.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pack_be16")]
#[inline(never)]
pub unsafe extern "C" fn pack_be16(dst: *mut u8, value: u16) {
    let reversed = value.swap_bytes();
    dst.write(reversed as u8);
    dst.add(1).write((reversed >> 8) as u8);
}

/// pack_be32 — original: `FUN_08261638` @ 0x08261638 (56 bytes, all code:
/// 13 instructions plus `bx lr`; 49 `bl` call sites, binary-scanned).
///
/// Writes `value` as four big-endian bytes at `dst`, needing no alignment.
///
/// The original reverses the word in registers first (`lsl #24`, two masked
/// `orr`s, `lsr #24`) and only then spills the four bytes least-significant
/// first to ascending addresses, walking `dst` with pre-indexed `strb`s.
/// The port keeps that two-step shape rather than collapsing it to four
/// shifted stores, so the codegen diff lines up with the original; the
/// observable effect is identical to [`store_be32`], and the dedicated text
/// section stops LLVM from merging the two onto one address.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pack_be32")]
#[inline(never)]
pub unsafe extern "C" fn pack_be32(dst: *mut u8, value: u32) {
    let reversed = value.swap_bytes();
    dst.write(reversed as u8);
    dst.add(1).write((reversed >> 8) as u8);
    dst.add(2).write((reversed >> 16) as u8);
    dst.add(3).write((reversed >> 24) as u8);
}

/// reverse_bytes32 — original: `FUN_082616d4` @ 0x082616d4 (28 bytes, all
/// code: 6 instructions plus `bx lr`; 2 `bl` call sites plus the tail `b`
/// from [`unpack_be32`] @ 0x0826178c, counted by decoding every B/BL word
/// in osos.dec).
///
/// Returns `value` with its four bytes reversed.
///
/// The private reverser of the wire-format cluster: unlike [`bswap32`]
/// @ 0x0805dc24, which round-trips the word through a stack slot, this one
/// stays in registers — `lsl #24`, `orr` of `value & 0xff00` shifted left 8,
/// `orr` of `value & 0xff0000` shifted right 8, `orr` of `value >> 24`. Same
/// observable result, separate firmware function, so it keeps its own text
/// section.
///
/// [`bswap32`]: crate::util::bswap::bswap32
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.reverse_bytes32")]
#[inline(never)]
pub extern "C" fn reverse_bytes32(value: u32) -> u32 {
    value.swap_bytes()
}

/// reverse_bytes64 — original: `FUN_082616f0` @ 0x082616f0 (96 bytes, all
/// code: 23 instructions plus `bx lr`; 1 `bl` call site from [`pack_be64`]
/// @ 0x08261680 plus the tail `b` from [`unpack_be64`] @ 0x082617e8,
/// counted by decoding every B/BL word in osos.dec).
///
/// Returns `value` with its eight bytes reversed: the 64-bit twin of
/// [`reverse_bytes32`], and the only reverser the 64-bit pair uses.
///
/// The original takes the doubleword in `r0`/`r1` and returns
/// `(reverse_bytes32(hi), reverse_bytes32(lo))` — each half reversed and
/// the two halves swapped. It open-codes the swap as a mask/shift chain
/// over the whole 64-bit value, which leaves four provably-zero lane terms
/// in the instruction stream (`(lo & 0xff0000) << 24`, `(hi & 0xff) >> 8`
/// and friends); those are dead in the original and are simply not written
/// here. Its own text section keeps it off the other reversers' symbols.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.reverse_bytes64")]
#[inline(never)]
pub extern "C" fn reverse_bytes64(value: u64) -> u64 {
    value.swap_bytes()
}

/// unpack_be32 — original: `FUN_08261770` @ 0x08261770 (32 bytes, all
/// code: 7 instructions plus a tail branch; 60 `bl` call sites,
/// binary-scanned).
///
/// Reads four big-endian bytes at `src` and returns them as a `u32`,
/// needing no alignment.
///
/// The original gathers the bytes into a little-endian word (walking `src`
/// with pre-indexed `ldrb`s) and then tail-branches to the private
/// register-only byte reverse @ 0x082616d4, ported here as
/// [`reverse_bytes32`]; the port folds that reverse in, since LLVM inlines
/// an equal-bodied leaf call anyway. The observable
/// effect is identical to [`load_be32`], and the dedicated text section
/// stops LLVM from merging the two onto one address.
///
/// Ghidra reports this function as 60 bytes, which runs 0x2c bytes past
/// the tail branch at 0x0826178c and swallows the separately-linked 64-bit
/// unpack that starts at 0x08261790. The 32-byte extent above is decoded
/// from the raw words.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.unpack_be32")]
#[inline(never)]
pub unsafe extern "C" fn unpack_be32(src: *const u8) -> u32 {
    let gathered = src.read() as u32
        | (src.add(1).read() as u32) << 8
        | (src.add(2).read() as u32) << 16
        | (src.add(3).read() as u32) << 24;
    gathered.swap_bytes()
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

    #[test]
    fn store_u32_be_bytes_matches_independent_reference_without_clobbering() {
        for value in [0, 1, 0x0000_ff00, 0x8000_0001, 0x1234_5678, u32::MAX] {
            for offset in [1usize, 2, 3, 5] {
                let mut actual = [0xa5u8; 12];
                let mut expected = actual;
                expected[offset..offset + 4].copy_from_slice(&value.to_be_bytes());

                unsafe { store_u32_be_bytes(actual.as_mut_ptr().add(offset), value) };

                assert_eq!(actual, expected, "value={value:#010x}, offset={offset}");
            }
        }
    }

    /// Two bytes, most significant at the lowest address, at every
    /// misalignment, with the neighbouring packet bytes untouched.
    #[test]
    fn pack_be16_writes_exactly_two_big_endian_bytes() {
        for value in [0u16, 1, 0x00ff, 0xff00, 0x7fff, 0x8001, 0x1234, u16::MAX] {
            for offset in 0..6usize {
                let mut actual = [0xa5u8; 12];
                let mut expected = actual;
                expected[offset..offset + 2].copy_from_slice(&value.to_be_bytes());

                unsafe { pack_be16(actual.as_mut_ptr().add(offset), value) };

                assert_eq!(actual, expected, "value={value:#06x}, offset={offset}");
            }
        }

        // A little-endian store would give [0x34, 0x12].
        let mut buf = [0u8; 2];
        unsafe { pack_be16(buf.as_mut_ptr(), 0x1234) };
        assert_eq!(buf, [0x12, 0x34]);
    }

    /// The most significant byte lands at the lowest address — the property
    /// the wire format depends on, and the one a stray `swap_bytes` would
    /// invert.
    #[test]
    fn pack_be32_writes_most_significant_byte_first() {
        let mut buf = [0u8; 4];
        unsafe { pack_be32(buf.as_mut_ptr(), 0x0102_0304) };
        assert_eq!(buf, [1, 2, 3, 4]);

        unsafe { pack_be32(buf.as_mut_ptr(), 0xdead_beef) };
        assert_eq!(buf, [0xde, 0xad, 0xbe, 0xef]);

        // A little-endian store would give [0x04, 0x03, 0x02, 0x01].
        unsafe { pack_be32(buf.as_mut_ptr(), 0x0000_00ff) };
        assert_eq!(buf, [0, 0, 0, 0xff]);
    }

    /// Every single-byte lane, at every misalignment, without disturbing a
    /// neighbouring byte: the packers are called on cursors inside packet
    /// buffers whose surrounding bytes are already filled in.
    #[test]
    fn pack_be32_touches_exactly_four_bytes_at_every_misalignment() {
        for value in [
            0u32,
            1,
            0x0000_00ff,
            0x0000_ff00,
            0x00ff_0000,
            0xff00_0000,
            0x8000_0001,
            0x1234_5678,
            u32::MAX,
        ] {
            for offset in 0..8usize {
                let mut actual = [0xa5u8; 16];
                let mut expected = actual;
                expected[offset..offset + 4].copy_from_slice(&value.to_be_bytes());

                unsafe { pack_be32(actual.as_mut_ptr().add(offset), value) };

                assert_eq!(actual, expected, "value={value:#010x}, offset={offset}");
            }
        }
    }

    /// The 0x0826xxxx packer and the 0x083816cc store are separate firmware
    /// functions with one contract; they must never disagree.
    #[test]
    fn pack_be32_agrees_with_store_be32() {
        for value in [0u32, 1, 0x0100_0001, 0x8000_0000, 0xdead_beef, u32::MAX] {
            let mut packed = [0u8; 4];
            let mut stored = [0u8; 4];
            unsafe {
                pack_be32(packed.as_mut_ptr(), value);
                store_be32(stored.as_mut_ptr(), value);
            }
            assert_eq!(packed, stored, "value={value:#010x}");
            assert_eq!(unsafe { load_be32(packed.as_ptr()) }, value);
        }
    }

    /// A byte reverse is its own inverse, moves every lane to the mirrored
    /// lane, and agrees with the independently ported stack-spilling
    /// `bswap32` @ 0x0805dc24.
    #[test]
    fn reverse_bytes32_mirrors_every_lane() {
        assert_eq!(reverse_bytes32(0x0102_0304), 0x0403_0201);
        assert_eq!(reverse_bytes32(0), 0);
        assert_eq!(reverse_bytes32(1), 0x0100_0000);
        assert_eq!(reverse_bytes32(0x7fff_ffff), 0xffff_ff7f);
        assert_eq!(reverse_bytes32(u32::MAX), u32::MAX);

        for lane in 0..4 {
            let value = 0xa5u32 << (8 * lane);
            assert_eq!(reverse_bytes32(value), 0xa5u32 << (8 * (3 - lane)), "lane={lane}");
        }

        for value in [0u32, 1, 0x0000_ff00, 0x8000_0001, 0x1234_5678, 0xdead_beef, u32::MAX] {
            assert_eq!(reverse_bytes32(reverse_bytes32(value)), value);
            assert_eq!(reverse_bytes32(value), crate::util::bswap::bswap32(value));
        }
    }

    /// It is exactly the transform that turns a little-endian gather into a
    /// big-endian read — the contract `unpack_be32` tail-branches for.
    #[test]
    fn reverse_bytes32_converts_a_little_endian_gather_to_big_endian() {
        let buf = [0xdeu8, 0xad, 0xbe, 0xef];
        let gathered = u32::from_le_bytes(buf);
        assert_eq!(reverse_bytes32(gathered), 0xdead_beef);
        assert_eq!(reverse_bytes32(gathered), unsafe { unpack_be32(buf.as_ptr()) });
    }

    /// The 64-bit reverse is exactly "reverse each half, then swap the
    /// halves" — the decomposition the original's register pair encodes,
    /// and the one a half-swapped port would get subtly wrong.
    #[test]
    fn reverse_bytes64_reverses_each_half_and_swaps_them() {
        assert_eq!(reverse_bytes64(0x0102_0304_0506_0708), 0x0807_0605_0403_0201);
        assert_eq!(reverse_bytes64(0), 0);
        assert_eq!(reverse_bytes64(1), 0x0100_0000_0000_0000);
        assert_eq!(reverse_bytes64(0x7fff_ffff_ffff_ffff), 0xffff_ffff_ffff_ff7f);
        assert_eq!(reverse_bytes64(u64::MAX), u64::MAX);

        for value in [0u64, 1, 0x8000_0000, 0x0000_0001_0000_0000, 0xdead_beef_cafe_f00d, u64::MAX]
        {
            let (lo, hi) = (value as u32, (value >> 32) as u32);
            let expect = (reverse_bytes32(lo) as u64) << 32 | reverse_bytes32(hi) as u64;
            assert_eq!(reverse_bytes64(value), expect, "value={value:#018x}");
            assert_eq!(reverse_bytes64(reverse_bytes64(value)), value);
        }
    }

    /// Every single-byte lane travels to its mirror; a port that reversed
    /// only within each half would pass the all-ones cases and fail here.
    #[test]
    fn reverse_bytes64_mirrors_every_lane() {
        for lane in 0..8 {
            let value = 0xa5u64 << (8 * lane);
            assert_eq!(reverse_bytes64(value), 0xa5u64 << (8 * (7 - lane)), "lane={lane}");
        }
    }

    /// The byte at the lowest address is the most significant — if the
    /// folded-in `swap_bytes` were dropped, this would read 0x04030201.
    #[test]
    fn unpack_be32_reads_most_significant_byte_first() {
        assert_eq!(unsafe { unpack_be32([1u8, 2, 3, 4].as_ptr()) }, 0x0102_0304);
        assert_eq!(unsafe { unpack_be32([0xde, 0xad, 0xbe, 0xef].as_ptr()) }, 0xdead_beef);
        assert_eq!(unsafe { unpack_be32([0, 0, 0, 1].as_ptr()) }, 1);
        assert_eq!(unsafe { unpack_be32([0x80, 0, 0, 0].as_ptr()) }, 0x8000_0000);
        assert_eq!(unsafe { unpack_be32([0, 0, 0, 0].as_ptr()) }, 0);
        assert_eq!(unsafe { unpack_be32([0xff; 4].as_ptr()) }, u32::MAX);
    }

    /// Every misalignment, reading exactly the four bytes at the cursor and
    /// nothing on either side — packet parsers call this mid-buffer.
    #[test]
    fn unpack_be32_reads_exactly_four_bytes_at_every_misalignment() {
        let buf: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        for offset in 0..12usize {
            let want =
                u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
            assert_eq!(unsafe { unpack_be32(buf.as_ptr().add(offset)) }, want, "offset={offset}");
        }
    }

    /// The unpacker is the inverse of the packer over every single-byte
    /// lane, and agrees with the independently ported load_be32.
    #[test]
    fn unpack_be32_inverts_pack_be32_and_agrees_with_load_be32() {
        for value in [
            0u32,
            1,
            0x0000_00ff,
            0x0000_ff00,
            0x00ff_0000,
            0xff00_0000,
            0x8000_0001,
            0x1234_5678,
            0xdead_beef,
            u32::MAX,
        ] {
            for offset in 0..5usize {
                let mut buf = [0xa5u8; 12];
                unsafe { pack_be32(buf.as_mut_ptr().add(offset), value) };
                assert_eq!(
                    unsafe { unpack_be32(buf.as_ptr().add(offset)) },
                    value,
                    "value={value:#010x}, offset={offset}"
                );
                assert_eq!(
                    unsafe { unpack_be32(buf.as_ptr().add(offset)) },
                    unsafe { load_be32(buf.as_ptr().add(offset)) },
                    "value={value:#010x}, offset={offset}"
                );
            }
        }
    }
}

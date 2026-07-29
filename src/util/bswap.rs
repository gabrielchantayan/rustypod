//! Byte-order swap helpers — the endianness cluster @ 0x0805dc24..0x0805dd88.
//!
//! retailOS parses big-endian file formats (iTunesDB atoms, MPEG-4 boxes,
//! resource records) on a little-endian core; these four helpers are its
//! `htonl`/`htons` family. All are pure leaf functions — no hardware is
//! touched, so host tests prove complete behavior. Originals (sizes from
//! decomp/functions.csv; call counts from scanning osos.dec for `b`/`bl`
//! words, not osos.asm, which drops lines):
//!
//! - `bswap32` — `FUN_0805dc24` @ 0x0805dc24 (48 bytes; 166 call sites).
//!   Spills the argument word to the stack, re-reads its 4 bytes in
//!   reverse order into a second slot, loads that word back. Pure
//!   byte-reverse of a 32-bit value.
//! - `bswap16` — `FUN_0805dd48` @ 0x0805dd48 (32 bytes; 133 call sites).
//!   Same stack dance over the low 2 bytes; the result is re-read with
//!   `ldrh`, so the return value is the swapped low half zero-extended —
//!   the argument's top 16 bits are discarded.
//! - `bswap32_inplace` — `FUN_0805dd10` @ 0x0805dd10 (56 bytes; 77 call
//!   sites). Copies the 4 bytes at `ptr` to the stack (as two `ldrh`
//!   halfword loads), then stores them back reversed byte by byte.
//! - `bswap16_inplace` — `FUN_0805dd68` @ 0x0805dd68 (36 bytes; 27 call
//!   sites). Swaps the 2 bytes at `ptr` via one stack byte.
//!
//! Deviation: `bswap32_inplace`'s original reads with `ldrh`, which on the
//! ARM926EJ-S requires `ptr` to be 2-byte aligned (a misaligned `ldrh` is
//! unpredictable/rotated on ARMv5). The port reads byte-wise, so it is
//! alignment-agnostic; for every pointer the original supported the result
//! is identical. All stores were byte-wise in the original already.

/// bswap32 — original: `FUN_0805dc24` @ 0x0805dc24 (48 bytes).
///
/// Returns `value` with its 4 bytes reversed.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn bswap32(value: u32) -> u32 {
    value.swap_bytes()
}

/// bswap16 — original: `FUN_0805dd48` @ 0x0805dd48 (32 bytes).
///
/// Returns the low 16 bits of `value` byte-swapped, zero-extended (the
/// original's `ldrh` reload — the argument's top half is discarded).
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn bswap16(value: u32) -> u32 {
    (value as u16).swap_bytes() as u32
}

/// bswap32_inplace — original: `FUN_0805dd10` @ 0x0805dd10 (56 bytes).
///
/// Reverses the 4 bytes at `ptr` in place (see the module header for the
/// `ldrh` alignment deviation).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bswap32_inplace(ptr: *mut u8) {
    let bytes = [
        ptr.read_volatile(),
        ptr.add(1).read_volatile(),
        ptr.add(2).read_volatile(),
        ptr.add(3).read_volatile(),
    ];
    for (i, b) in bytes.into_iter().enumerate() {
        ptr.add(3 - i).write_volatile(b);
    }
}

/// bswap16_inplace — original: `FUN_0805dd68` @ 0x0805dd68 (36 bytes).
///
/// Swaps the 2 bytes at `ptr` in place.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bswap16_inplace(ptr: *mut u8) {
    let first = ptr.read_volatile();
    let second = ptr.add(1).read_volatile();
    ptr.write_volatile(second);
    ptr.add(1).write_volatile(first);
}

// ---------------------------------------------------------------------------
// The register-only pair @ 0x08076f48 / 0x08076f58.
//
// A second, independent implementation of the same operation, living in the
// general-utility block around 0x08076xxx (next to `os_malloc` @ 0x080769b8
// and the 16.16 fixed-point helpers). Where the 0x0805dxxx pair above spills
// through the stack, these do the swap entirely in registers — different
// object file, different optimization level, same job.
//
// They are kept as distinct ports because their *contracts* differ at the
// edges: `bswap16` above reloads through `ldrh` and so zero-extends, while
// `byteswap16` masks with `bic #0x00ff0000` and so passes the argument's
// top byte through. See `byteswap16`'s doc comment.
// ---------------------------------------------------------------------------

/// byteswap16 — original: `FUN_08076f48` @ 0x08076f48 (16 bytes; 60 call
/// sites, binary-scanned).
///
/// Byte-swaps a 16-bit value: `((v << 8) | (v >> 8)) & 0xff00ffff`.
///
/// The odd mask is the ADS narrowing of an `unsigned short` result. For a
/// genuine `u16` argument the shifted-left copy cannot reach bit 24, so the
/// only stray term is `(v & 0xff00) << 8` in byte 2 — one `bic` clears it,
/// which is cheaper than the `and #0xffff` a general narrowing would need.
/// The port reproduces the mask bit-for-bit rather than the intent, so a
/// caller that passes a full 32-bit word gets the original's exact answer;
/// for every `v <= 0xffff` it equals `(v as u16).swap_bytes() as u32`.
/// Every observed call site feeds it a zero-extended `ldrh` and stores the
/// result with `strh` (e.g. `FUN_080b16f0`, `FUN_080c0468`), so the
/// distinction never becomes visible in stock firmware.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn byteswap16(value: u32) -> u32 {
    ((value << 8) | (value >> 8)) & 0xff00_ffff
}

/// byteswap32 — original: `FUN_08076f58` @ 0x08076f58 (28 bytes; 23 call
/// sites, binary-scanned).
///
/// Full 32-bit byte reverse, assembled in registers:
/// `v << 24 | (v & 0xff00) << 8 | (v & 0xff0000) >> 8 | v >> 24`.
/// Semantically identical to `bswap32` above, so LLVM folds the two bodies
/// onto one address in the archive; review its codegen through either
/// symbol.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn byteswap32(value: u32) -> u32 {
    value.swap_bytes()
}

// ---------------------------------------------------------------------------
// The GUID-converter copy @ 0x080e965c.
//
// A third, independent instance of the same 32-bit byte reverse, living in
// the COM-style object code block around 0x080fxxxx. It is the register-only
// form again: mov/and/orr x2 + final orr + bx, 28 bytes — the same
// expression as `byteswap32` above, with the shifts accumulated in the
// opposite order (top byte first instead of bottom byte first).
//
// All 6 call sites (osos.asm) sit in two sibling functions, FUN_080fab9c
// and FUN_080fc3d8, which each pull a 12-byte struct out of a COM-style
// vtable object and byte-swap its three consecutive words — the classic
// fix-up for a GUID's three endian-sensitive fields (DWORD, WORD, WORD).
// Hence the name; the operation itself is a plain bswap32.
// ---------------------------------------------------------------------------

/// bswap32_guid_field — original: `FUN_080e965c` @ 0x080e965c (28 bytes;
/// 6 bl call sites, all inside FUN_080fab9c / FUN_080fc3d8).
///
/// Full 32-bit byte reverse, assembled in registers:
/// `v >> 24 | (v & 0xff0000) >> 8 | (v & 0xff00) << 8 | v << 24`.
/// Semantically identical to `bswap32` (0x0805dc24) and `byteswap32`
/// (0x08076f58), so LLVM folds all three bodies onto one address in the
/// archive; review its codegen through any of the three symbols.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn bswap32_guid_field(value: u32) -> u32 {
    value.swap_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bswap32_reverses_all_four_bytes() {
        assert_eq!(bswap32(0x1234_5678), 0x7856_3412);
        assert_eq!(bswap32(0), 0);
        assert_eq!(bswap32(0xffff_ffff), 0xffff_ffff);
        assert_eq!(bswap32(0x0000_00ff), 0xff00_0000);
        assert_eq!(bswap32(0x8000_0001), 0x0100_0080);
    }

    #[test]
    fn bswap32_is_an_involution() {
        for v in [0u32, 1, 0xdead_beef, 0x8000_0000, 0x00ff_ff00] {
            assert_eq!(bswap32(bswap32(v)), v);
        }
    }

    #[test]
    fn bswap16_swaps_low_half_and_zero_extends() {
        assert_eq!(bswap16(0x1234), 0x3412);
        assert_eq!(bswap16(0xff00), 0x00ff);
        assert_eq!(bswap16(0), 0);
        // The original's ldrh reload discards the argument's top half.
        assert_eq!(bswap16(0xabcd_1234), 0x3412);
        assert_eq!(bswap16(0xffff_0000), 0);
    }

    #[test]
    fn bswap32_inplace_reverses_buffer_bytes() {
        let mut buf = [0x12u8, 0x34, 0x56, 0x78];
        unsafe { bswap32_inplace(buf.as_mut_ptr()) };
        assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);
        // Involution.
        unsafe { bswap32_inplace(buf.as_mut_ptr()) };
        assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn bswap32_inplace_touches_exactly_four_bytes() {
        let mut buf = [0xaau8, 1, 2, 3, 4, 0xbb];
        unsafe { bswap32_inplace(buf.as_mut_ptr().add(1)) };
        assert_eq!(buf, [0xaa, 4, 3, 2, 1, 0xbb]);
    }

    #[test]
    fn bswap16_inplace_swaps_the_pair() {
        let mut buf = [0x12u8, 0x34, 0x99];
        unsafe { bswap16_inplace(buf.as_mut_ptr()) };
        assert_eq!(buf, [0x34, 0x12, 0x99], "third byte untouched");
    }

    /// Over the whole 16-bit domain the 0x08076f48 form is exactly a u16
    /// byte swap — the property its callers rely on.
    #[test]
    fn byteswap16_is_a_u16_swap_over_the_whole_domain() {
        for v in 0u32..=0xffff {
            assert_eq!(byteswap16(v), (v as u16).swap_bytes() as u32, "v={v:#06x}");
        }
    }

    /// Above 0xffff the mask leaks the argument's top byte into the result
    /// — the documented deviation from `bswap16`'s `ldrh` zero-extension.
    /// Values are the exact `((v << 8) | (v >> 8)) & 0xff00ffff` reference.
    #[test]
    fn byteswap16_passes_the_top_byte_through() {
        for v in [0xabcd_1234u32, 0xffff_ffff, 0x8000_0000, 0x00ff_0000, 0x1234_5678] {
            let want = ((v << 8) | (v >> 8)) & 0xff00_ffff;
            assert_eq!(byteswap16(v), want, "v={v:#010x}");
        }
        // Concretely: 0xffffffff -> 0xff00ffff, not bswap16's 0xffff.
        assert_eq!(byteswap16(0xffff_ffff), 0xff00_ffff);
        assert_eq!(bswap16(0xffff_ffff), 0x0000_ffff);
    }

    /// The register-only 32-bit form agrees with the stack-based one
    /// everywhere, including the four single-byte lanes and the extremes.
    #[test]
    fn byteswap32_agrees_with_bswap32() {
        for v in [
            0u32,
            1,
            0xffff_ffff,
            0x0000_00ff,
            0x0000_ff00,
            0x00ff_0000,
            0xff00_0000,
            0x1234_5678,
            0xdead_beef,
            0x8000_0001,
        ] {
            let want = v << 24 | (v & 0xff00) << 8 | (v & 0xff_0000) >> 8 | v >> 24;
            assert_eq!(byteswap32(v), want, "v={v:#010x}");
            assert_eq!(byteswap32(v), bswap32(v), "v={v:#010x}");
            assert_eq!(byteswap32(byteswap32(v)), v, "involution v={v:#010x}");
        }
    }

    /// The GUID-converter copy reproduces the reference C expression
    /// `v >> 24 | (v & 0xff0000) >> 8 | (v & 0xff00) << 8 | v << 24`
    /// exactly and agrees with the other two bswap32 instances.
    #[test]
    fn bswap32_guid_field_matches_the_reference_expression() {
        for v in [
            0u32,
            1,
            0xffff_ffff,
            0x0000_00ff,
            0x0000_ff00,
            0x00ff_0000,
            0xff00_0000,
            0x1234_5678,
            0xdead_beef,
            0x8000_0001,
            // A plausible GUID first field: endian-flipped.
            0x8b7c_3f2a,
        ] {
            let want = v >> 24 | (v & 0xff_0000) >> 8 | (v & 0xff00) << 8 | v << 24;
            assert_eq!(bswap32_guid_field(v), want, "v={v:#010x}");
            assert_eq!(bswap32_guid_field(v), bswap32(v), "v={v:#010x}");
            assert_eq!(bswap32_guid_field(v), byteswap32(v), "v={v:#010x}");
            assert_eq!(bswap32_guid_field(bswap32_guid_field(v)), v, "involution v={v:#010x}");
        }
    }

    /// Exhaustive over all single-byte and two-byte lane combinations —
    /// the four byte lanes each land in the reversed position.
    #[test]
    fn bswap32_guid_field_reverses_every_byte_lane() {
        for a in 0u32..=0xff {
            for b in 0u32..=0xff {
                let v = a | b << 8;
                let want = u32::from_le_bytes(v.to_be_bytes());
                assert_eq!(bswap32_guid_field(v), want, "v={v:#010x}");
            }
        }
    }
}

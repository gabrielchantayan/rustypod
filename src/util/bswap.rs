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
}

//! `object_flag_low_nibble` — original: `FUN_08160cfc` @ 0x08160cfc
//! (12 bytes).
//!
//! Loads byte `+0x0d` from an opaque application object, masks it with
//! `0x0f`, and returns the low four bits. In its recovered direct caller
//! (`FUN_08160888`), the result selects an entry from a table at the caller's
//! `+0x18`; the object's wider layout and the high nibble's meaning remain
//! unidentified.
//!
//! Sources: `ipod-decomp/decomp/c/014/08160cfc_FUN_08160cfc.c`, the
//! `ldrb r0, [r0, #0xd]; and r0, r0, #0xf; bx lr` sequence at 0x08160cfc in
//! `ipod-decomp/decomp/osos.asm`, and direct calls in
//! `decomp/c/014/08160888_FUN_08160888.c`.
//!
//! Deviation: none.

/// Returns the low nibble of byte `+0x0d` in an opaque application object.
///
/// # Safety
///
/// `object` must point into a readable allocation that includes byte `+0x0d`.
/// The pointer may be unaligned because the retail routine performs a byte
/// load.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_flag_low_nibble(object: *const u8) -> u8 {
    object.add(0x0d).read() & 0x0f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_every_low_nibble_without_touching_the_object() {
        let mut object = [0xa5u8; 0x20];

        for high_nibble in 0u8..=0x0f {
            for low_nibble in 0u8..=0x0f {
                object[0x0d] = high_nibble << 4 | low_nibble;
                let before = object;

                assert_eq!(
                    unsafe { object_flag_low_nibble(object.as_ptr()) },
                    low_nibble,
                    "byte={:#04x}",
                    object[0x0d]
                );
                assert_eq!(object, before, "read changed object for byte={:#04x}", before[0x0d]);
            }
        }
    }
}

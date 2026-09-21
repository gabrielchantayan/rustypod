//! `tagged_pointer_u16_init` — original: `FUN_082d6648` @ 0x082d6648 (16 bytes;
//! **3 unconditional plain `bl` call sites**, zero predicated `bl` call sites).
//!
//! # Extent, binary-verified
//!
//! Raw `osos.dec` words `e1c010b0 e1c020b2 e5803004 e12fff1e` decode to
//! `strh r1,[r0]`; `strh r2,[r0,#2]`; `str r3,[r0,#4]`; `bx lr`. This is the
//! complete 16-byte body at 0x082d6648..0x082d6657; 0x082d6658 starts the next
//! independent function (`mov r1,#0`). Whole-image A32 decoding finds inbound
//! plain BLs at 0x08084840, 0x082cb42c, and 0x082cb440, with no predicated BLs.
//!
//! # Algorithm
//!
//! Writes an eight-byte tagged-pointer record in place: the low 16 bits of
//! `tag`, the low 16 bits of `state`, and a 32-bit target word. All three known
//! callers initialize records with `(0, 6, record + 8)`. The function preserves
//! `this` in r0, although callers ignore that incidental return value.
//!
//! # Deliberate deviations
//!
//! None. `target` is `u32`, not a Rust pointer, because the firmware record
//! contains an ARM 32-bit address even when host tests use 64-bit pointers.

/// Initializes an eight-byte tagged-pointer record and returns `this`.
///
/// # Safety
///
/// `this` must be valid for two aligned 16-bit stores at offsets 0 and 2 and
/// one aligned 32-bit store at offset 4. The retail body has no null or bounds
/// checks and discards high bits of `tag` and `state`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_pointer_u16_init(
    this: *mut u8,
    tag: u32,
    state: u32,
    target: u32,
) -> *mut u8 {
    unsafe {
        this.cast::<u16>().write_volatile(tag as u16);
        this.add(2).cast::<u16>().write_volatile(state as u16);
        this.add(4).cast::<u32>().write_volatile(target);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_all_fields_at_their_arm_offsets() {
        let mut words = [0xfeed_faceu32, 0xa5a5_5a5a, 0xdead_beef];
        let record = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };

        let returned = unsafe {
            tagged_pointer_u16_init(record, 0x1234_5678, 0x9abc_def0, 0x2468_ace0)
        };

        assert_eq!(returned, record);
        assert_eq!(words, [0xfeed_face, 0xdef0_5678, 0x2468_ace0]);
    }

    #[test]
    fn zero_values_overwrite_every_record_byte() {
        let mut words = [0xffff_ffffu32, 0xffff_ffff];

        unsafe { tagged_pointer_u16_init(words.as_mut_ptr().cast(), 0, 0, 0) };

        assert_eq!(words, [0, 0]);
    }
}

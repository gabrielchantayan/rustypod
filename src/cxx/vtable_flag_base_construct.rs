//! `vtable_flag_base_construct` — `FUN_08135788` @ **0x08135788**.
//! True extent [0x08135788,0x081357a0): 20 instruction bytes and the
//! four-byte vtable literal at 0x0813579c, total 24 bytes. The next real
//! function begins with `cmp r0,#0` at 0x081357a0.
//! Whole-image aligned ARM decoding verifies two incoming plain BLs at
//! 0x081b6970 and 0x081d17d0, zero predicated BLs; no outgoing BL/BLX.
//!
//! Install vtable 0x08984948 at +0, clear only byte +4, and return the
//! unchanged receiver. Padding and derived fields remain untouched.
//! Deliberate deviations: none; retain a target-width vtable address on
//! hosts rather than inventing a class identity or native vtable pointer.

pub const VTABLE_FLAG_BASE_VTABLE_ADDRESS: u32 = 0x0898_4948;

/// # Safety
/// `this` must be four-byte aligned and point to at least five writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_flag_base_construct(this: *mut u8) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write_volatile(VTABLE_FLAG_BASE_VTABLE_ADDRESS);
        this.add(4).write_volatile(0);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct Storage([u8; 16]);

    #[test]
    fn clears_every_flag_value_without_touching_padding_or_derived_fields() {
        for flag in 0..=u8::MAX {
            let mut storage = Storage([0xa5; 16]);
            storage.0[8] = flag;
            let object = unsafe { storage.0.as_mut_ptr().add(4) };
            let returned = unsafe { vtable_flag_base_construct(object) };
            let mut expected = [0xa5; 16];
            expected[4..8].copy_from_slice(&VTABLE_FLAG_BASE_VTABLE_ADDRESS.to_ne_bytes());
            expected[8] = 0;
            assert_eq!(returned, object);
            assert_eq!(storage.0, expected);
            unsafe { vtable_flag_base_construct(object) };
            assert_eq!(storage.0, expected);
        }
    }
}

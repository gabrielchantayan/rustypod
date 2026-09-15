//! Object flag-mask containment — `FUN_08137ea4` @ `0x08137ea4`.
//!
//! True extent: 20 bytes (`0x08137ea4..0x08137eb8`); the next distinct
//! function begins with `push {r4, r5, r6, r7, r8, lr}` at `0x08137eb8`.
//! A decode of every ARM B/BL word in `osos.dec` finds five direct call sites,
//! all plain unconditional `bl` (0x08208d68, 0x0820bf40, 0x08215448,
//! 0x0821a630, and 0x0822c390); there are no predicated `bl` call sites.
//!
//! Loads the object's aligned flag word at +0x20 and returns one when it
//! contains every bit requested by `mask`; an empty mask is vacuously
//! contained. The original is `ldr; tst; movne; moveq; bx lr`. Deliberate
//! deviations: none.

const FLAGS_OFFSET: usize = 0x20;

/// Returns one when the +0x20 flag word of `object` contains every `mask` bit.
///
/// # Safety
///
/// `object` must be valid to read an aligned `u32` at byte offset +0x20. This
/// is the original's unguarded load contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_flags_contain(object: *const u8, mask: u32) -> u32 {
    let flags = (object.add(FLAGS_OFFSET) as *const u32).read();
    u32::from(mask & !flags == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_mask_is_contained() {
        let object = [0u32; 9];

        assert_eq!(unsafe { object_flags_contain(object.as_ptr().cast(), 0) }, 1);
    }

    #[test]
    fn complete_requested_mask_is_contained() {
        let mut object = [0u32; 9];
        object[8] = 0xa5a5_00f0;

        assert_eq!(unsafe { object_flags_contain(object.as_ptr().cast(), 0x00a0_00d0) }, 1);
    }

    #[test]
    fn partially_present_mask_is_not_contained() {
        let mut object = [0u32; 9];
        object[8] = 0x0000_0001;

        assert_eq!(unsafe { object_flags_contain(object.as_ptr().cast(), 0x0000_0003) }, 0);
    }
}

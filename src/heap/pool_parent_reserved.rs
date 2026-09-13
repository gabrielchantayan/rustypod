//! `pool_parent_reserved_get` — original: `FUN_081fbf68` @ **0x081fbf68**
//! (8 bytes; 6 verified direct `bl` call sites, all unconditional:
//! `0x08207944`, `0x082079b8`, `0x08207b2c`, `0x08207fa8`, `0x0820802c`,
//! and `0x08208054`).
//!
//! The complete body is `ldr r0, [r0, #0x40]; bx lr`: it returns the
//! `parent_reserved` word of a block-manager [`PoolBase`]. The next separately
//! linked accessor starts at 0x081fbf70, confirming the 8-byte extent. The
//! getter does not NULL-check `this`; neither does the firmware. It has no
//! deliberate deviations.

use crate::heap::block_deque::PoolBase;

/// Returns the block-manager pool base's `parent_reserved` word.
///
/// `this` must point to a valid [`PoolBase`], as required by the original
/// unchecked `ldr` at +0x40.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pool_parent_reserved_get")]
pub unsafe extern "C" fn pool_parent_reserved_get(this: *const PoolBase) -> u32 {
    (*this).parent_reserved
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn returns_the_full_reserved_word() {
        let mut object = MaybeUninit::<PoolBase>::zeroed();

        unsafe {
            for expected in [0, 1, 0x8000_0000, u32::MAX] {
                (*object.as_mut_ptr()).parent_reserved = expected;
                assert_eq!(pool_parent_reserved_get(object.as_ptr()), expected);
            }
        }
    }
}

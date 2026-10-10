//! Resource digest comparison — `FUN_08070960` @ 0x08070960.
//! True extent: [0x08070960, 0x0807099c), 60 instruction bytes, no literals.
//! Two plain BLs, zero predicated BLs; two plain incoming BLs and zero
//! predicated incoming BLs. The next function starts with PUSH at 0x0807099c.
//!
//! Prepare each resource state through resource_load_dispatch(state, -1, 0),
//! ignoring its result, then compare the 20-byte digest at state+0x3c using
//! canonical memcmp. Return the exact signed first-differing-byte difference.
//! Deliberate deviations: none in behavior; LLVM chooses the call/return shape
//! instead of reproducing the original's explicit memcmp tail branch.

#[cfg(not(target_arch = "arm"))]
use crate::resource_load_dispatch::resource_load_dispatch;

// The existing ARM port exports global assembly rather than a Rust item.
#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn resource_load_dispatch(state: *mut u8, selector: i32, payload: u32) -> u32;
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_digest_compare(left: *mut u8, right: *mut u8) -> i32 {
    resource_load_dispatch(left, -1, 0);
    resource_load_dispatch(right, -1, 0);
    crate::memcmp::memcmp(left.add(0x3c), right.add(0x3c), 20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_unsigned_difference_at_every_digest_byte() {
        // Word alignment and complete state storage for the real dispatcher.
        let mut left = [0u32; 21];
        let mut right = [0u32; 21];
        left[9] = 0x100;
        right[9] = 0x100;
        unsafe {
            let a = left.as_mut_ptr().cast::<u8>();
            let b = right.as_mut_ptr().cast::<u8>();
            for index in 0..20 {
                a.add(0x3c + index).write(0xff);
                b.add(0x3c + index).write(0x01);
                // A later opposite mismatch must not determine the result.
                if index + 1 < 20 {
                    a.add(0x3c + index + 1).write(0);
                    b.add(0x3c + index + 1).write(0xff);
                }
                assert_eq!(resource_digest_compare(a, b), 254);
                assert_eq!(resource_digest_compare(b, a), -254);
                core::ptr::write_bytes(a.add(0x3c), 0, 20);
                core::ptr::write_bytes(b.add(0x3c), 0, 20);
            }
        }
    }

    #[test]
    fn ignores_surrounding_state_and_accepts_aliasing() {
        let mut left = [0u32; 21];
        let mut right = [u32::MAX; 21];
        left[9] = 0x100;
        right[9] = 0x100;
        right[15..20].fill(0);
        unsafe {
            let a = left.as_mut_ptr().cast::<u8>();
            let b = right.as_mut_ptr().cast::<u8>();
            assert_eq!(resource_digest_compare(a, b), 0);
            assert_eq!(resource_digest_compare(a, a), 0);
        }
    }
}

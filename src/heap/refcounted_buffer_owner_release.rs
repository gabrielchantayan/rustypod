//! `refcounted_buffer_owner_release` — `FUN_08044900` @ 0x08044900.
//! True extent: 28 bytes [0x08044900,0x0804491c), before an independent
//! field-query entry. Verified inbound calls: one plain BL at 0x08095ef4
//! and one BLNE at 0x080da950; no inbound B. Body: zero BLs and one BEQ
//! tail branch to the already ported destructor at 0x080aa408.
//!
//! NULL is ignored. Otherwise decrement the u32 count at +4 modulo 2^32,
//! store it, and destroy the owned buffers and owner only when it becomes
//! zero. An initial zero wraps to u32::MAX without destruction.
//! Deliberate deviation: Rust does not guarantee the conditional tail branch.

use crate::heap::refcounted_buffer_owner_destroy::refcounted_buffer_owner_destroy;

/// # Safety
/// A non-NULL owner must have an aligned writable count word at +4. When
/// that count is one, it must also satisfy `refcounted_buffer_owner_destroy`'s
/// allocation and owned-field requirements. No synchronization is provided.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn refcounted_buffer_owner_release(owner: *mut u32) {
    if owner.is_null() {
        return;
    }
    let count = owner.add(1);
    let remaining = count.read().wrapping_sub(1);
    count.write(remaining);
    if remaining == 0 {
        refcounted_buffer_owner_destroy(owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};

    #[test]
    fn null_and_nonfinal_counts_preserve_owner() {
        let _heap = mock_heap();
        unsafe { refcounted_buffer_owner_release(core::ptr::null_mut()); }
        assert_eq!(free_log().0, 0);
        for initial in [0u32, 2, 3, 0x8000_0000, u32::MAX] {
            let mut owner = [0xa55a_5aa5u32; 17];
            owner[1] = initial;
            let mut expected = owner;
            expected[1] = initial.wrapping_sub(1);
            unsafe { refcounted_buffer_owner_release(owner.as_mut_ptr()); }
            assert_eq!(owner, expected);
            assert_eq!(free_log().0, 0);
        }
    }

    #[test]
    fn repeated_release_destroys_only_at_zero() {
        let _heap = mock_heap();
        let mut owner = [0x1234_5678u32; 17];
        owner[1] = 3;
        owner[6..=10].fill(0);
        let mut expected = owner;
        for remaining in [2, 1, 0] {
            unsafe { refcounted_buffer_owner_release(owner.as_mut_ptr()); }
            expected[1] = remaining;
            if remaining == 0 { expected[0] = 0; }
            assert_eq!(owner, expected);
            assert_eq!(free_log().0, usize::from(remaining == 0));
        }
        assert_eq!(free_log(), (1, owner.as_mut_ptr().cast(), 4));
    }
}

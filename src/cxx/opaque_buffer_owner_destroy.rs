//! `opaque_buffer_owner_destroy` — original: `FUN_082a8948` @ **0x082a8948**.
//!
//! True extent: 60 bytes (56 instruction bytes through 0x082a897c and the
//! vtable literal at 0x082a8980); the next function starts at 0x082a8984.
//! Raw A32 verifies two plain outbound BLs and one BLNE, all to the already
//! ported `operator_delete_tag3` @ 0x082aad14. Whole-image branch decoding
//! finds two plain inbound BLs (0x082a7bc4, 0x082a893c), no predicated BLs;
//! both callers subsequently release the owner through tag-2 delete.
//!
//! Install vtable 0x089a8994, release the allocation word at +0x14 only when
//! byte +0x18 is nonzero, then release words +0x2c and +0x30 unconditionally.
//! Return the original owner without clearing its fields or freeing it.
//! Deliberate deviations: use the existing Rust tag-3 delete port rather
//! than a retail-address seam; volatile accesses preserve stores and loads
//! across releases. Target pointer words remain u32 even on the host.

use crate::heap::veneers::operator_delete_tag3;

/// Destroys a live, writable, aligned owner of at least 13 target words.
/// Allocation words must satisfy the tag-3 delete contract when released.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_buffer_owner_destroy(owner: *mut u32) -> *mut u32 {
    unsafe { destroy_with(owner, |allocation| operator_delete_tag3(allocation)) }
}

#[inline(always)]
unsafe fn destroy_with(owner: *mut u32, mut release: impl FnMut(*mut u8)) -> *mut u32 {
    unsafe {
        owner.write_volatile(0x089a_8994);
        if owner.cast::<u8>().add(0x18).read_volatile() != 0 {
            release(owner.add(5).read_volatile() as usize as *mut u8);
        }
        release(owner.add(11).read_volatile() as usize as *mut u8);
        release(owner.add(12).read_volatile() as usize as *mut u8);
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    #[test]
    fn ownership_is_a_byte_and_other_fields_survive() {
        // Allocation words are opaque tokens consumed only by the recorder,
        // never dereferenced; no low-address pointer fixture is needed.
        for flag in [0u8, 1, 0x80, 0xff] {
            let mut words = [0x1122_3344u32; 15];
            words[6] = 0xaabb_cc00 | u32::from(flag);
            words[5] = 0x1234;
            words[11] = 0x5678;
            words[12] = 0x9abc;
            let before = words;
            let owner = unsafe { words.as_mut_ptr().add(1) };
            // Move the fixture to the guarded interior of the array.
            unsafe { core::ptr::copy(words.as_ptr(), owner, 13) };
            let mut expected = words;
            expected[1] = 0x089a_8994;
            let mut released = std::vec::Vec::new();
            let returned = unsafe { destroy_with(owner, |allocation| {
                assert_eq!(owner.read_volatile(), 0x089a_8994);
                released.push(allocation as usize as u32);
            }) };
            assert_eq!(returned, owner);
            assert_eq!(words, expected);
            assert_eq!(words[0], before[0]);
            assert_eq!(words[14], before[14]);
            let expected_releases = if flag == 0 {
                std::vec![0x5678, 0x9abc]
            } else {
                std::vec![0x1234, 0x5678, 0x9abc]
            };
            assert_eq!(released, expected_releases);
        }
    }

    #[test]
    fn preserves_null_releases_and_reloads_after_each_release() {
        let mut words = [0u32; 13];
        words[6] = 1;
        let owner = words.as_mut_ptr();
        let mut released = std::vec::Vec::new();
        unsafe { destroy_with(owner, |allocation| {
            released.push(allocation as usize as u32);
            match released.len() {
                1 => owner.add(11).write_volatile(0x1234),
                2 => owner.add(12).write_volatile(0x5678),
                _ => (),
            }
        }) };
        assert_eq!(released, [0, 0x1234, 0x5678]);
        assert_eq!(words[5], 0);
        assert_eq!(words[6], 1);
        assert_eq!(words[11], 0x1234);
        assert_eq!(words[12], 0x5678);
    }
}

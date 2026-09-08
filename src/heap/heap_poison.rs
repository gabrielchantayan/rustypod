//! `heap_poison` — heap debug-fill helper.
//!
//! Original: `FUN_0805f440` @ 0x0805f440 (92 bytes exactly,
//! 0x0805f440..0x0805f49c; the following word is the literal pointer
//! 0x08a0ea04 and the next independent entry is the veneer at 0x0805f4a0).
//! A complete raw `osos.dec` ARM B/BL decode found 19 inbound direct calls:
//! all are unconditional `bl` instructions (no direct `b` tail calls and no
//! predicated calls). The sole callee is the ported [`crate::libc::memchr::memchr`]
//! at 0x08031180.
//!
//! The helper overwrites `len` bytes with the current large-allocation tag.
//! After each byte, it advances that shared tag by `(next_dst & 15) + 17`,
//! wrapping as an ARM byte add does. It then scans the just-filled range for
//! the final tag byte and, on a match, advances the tag once more by 63.
//! Consequently a nonzero length always takes that final increment; zero
//! length still executes the bounded scan but leaves the tag unchanged.
//!
//! Deviation: the retail byte lives at absolute address 0x08a0ea04. The port
//! shares [`crate::drivers::ata_cmd::LARGE_ALLOC_TAG`], the existing model of
//! that same byte used by `traced_alloc`, so host tests and target setup have
//! one coherent state cell.

use crate::drivers::ata_cmd::LARGE_ALLOC_TAG;
use crate::libc::memchr::memchr;

/// heap_poison — original: `FUN_0805f440` @ 0x0805f440 (92 bytes; 19 direct
/// unconditional `bl` callers, no direct branches or predicated callers).
///
/// `dst` must designate at least `len` writable bytes. The routine preserves
/// no contents in that range and mutates the shared large-allocation tag.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn heap_poison(dst: *mut u8, len: u32) {
    let tag = core::ptr::addr_of_mut!(LARGE_ALLOC_TAG);
    let mut offset = 0u32;
    while offset != len {
        let state = unsafe { tag.read_volatile() };
        unsafe { dst.add(offset as usize).write_volatile(state) };
        let next_address_low = ((dst as usize).wrapping_add(offset as usize + 1) & 15) as u8;
        unsafe { tag.write_volatile(state.wrapping_add(next_address_low).wrapping_add(17)) };
        offset = offset.wrapping_add(1);
    }

    let final_state = unsafe { tag.read_volatile() };
    if !unsafe { memchr(dst, final_state as i32, len as usize) }.is_null() {
        unsafe { tag.write_volatile(final_state.wrapping_add(63)) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::TRACED_ALLOC_TEST_LOCK;

    struct TagReset(u8);

    impl Drop for TagReset {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(LARGE_ALLOC_TAG).write_volatile(self.0) };
        }
    }

    fn reference(dst_address: usize, len: usize, initial_tag: u8) -> (std::vec::Vec<u8>, u8) {
        let mut bytes = std::vec::Vec::with_capacity(len);
        let mut state = initial_tag;
        for offset in 0..len {
            bytes.push(state);
            state = state
                .wrapping_add(((dst_address + offset + 1) & 15) as u8)
                .wrapping_add(17);
        }
        if bytes.contains(&state) {
            state = state.wrapping_add(63);
        }
        (bytes, state)
    }

    #[test]
    fn matches_the_raw_byte_loop_across_alignments_lengths_and_tags() {
        let _guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let old_tag = unsafe { core::ptr::addr_of!(LARGE_ALLOC_TAG).read_volatile() };
        let _reset = TagReset(old_tag);

        for alignment in 0..16 {
            for len in 0..=64 {
                for initial_tag in [0, 1, 0x61, 0xa5, 0xff] {
                    let mut storage = [0xccu8; 96];
                    let dst = unsafe { storage.as_mut_ptr().add(16 + alignment) };
                    let (expected_bytes, expected_tag) = reference(dst as usize, len, initial_tag);
                    unsafe {
                        core::ptr::addr_of_mut!(LARGE_ALLOC_TAG).write_volatile(initial_tag);
                        heap_poison(dst, len as u32);
                    }
                    assert_eq!(&storage[16 + alignment..16 + alignment + len], expected_bytes.as_slice(),
                        "alignment={alignment}, len={len}, tag={initial_tag:#x}");
                    assert!(storage[..16 + alignment].iter().all(|&byte| byte == 0xcc));
                    assert!(storage[16 + alignment + len..].iter().all(|&byte| byte == 0xcc));
                    assert_eq!(unsafe { core::ptr::addr_of!(LARGE_ALLOC_TAG).read_volatile() }, expected_tag,
                        "alignment={alignment}, len={len}, tag={initial_tag:#x}");
                }
            }
        }
    }

    #[test]
    fn zero_length_scans_without_writing_or_advancing_the_tag() {
        let _guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let old_tag = unsafe { core::ptr::addr_of!(LARGE_ALLOC_TAG).read_volatile() };
        let _reset = TagReset(old_tag);
        let mut storage = [0x5au8; 8];
        unsafe {
            core::ptr::addr_of_mut!(LARGE_ALLOC_TAG).write_volatile(0x42);
            heap_poison(storage.as_mut_ptr(), 0);
        }
        assert_eq!(storage, [0x5a; 8]);
        assert_eq!(unsafe { core::ptr::addr_of!(LARGE_ALLOC_TAG).read_volatile() }, 0x42);
    }
}

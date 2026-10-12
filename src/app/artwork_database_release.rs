//! Artwork database cleanup — `FUN_08044d3c` @ `0x08044d3c`, 28 bytes.
//!
//! Raw A32 extent is `0x08044d3c..0x08044d58`; the next word is an
//! independent PUSH. Whole-image word decoding verifies one plain inbound BL
//! (`0x08068f94`), one predicated BLNE (`0x0805824c`), and one plain outbound
//! BL (`0x08044d48` to `0x080490b8`), with no predicated outbound calls.
//! Release the artwork database word at owner+0xf9c unconditionally, then
//! clear it. The Artwork/ArtworkDB path in the caller establishes its role.
//!
//! Deliberate deviation: reuse the existing media allocation release ops seam
//! rather than duplicate the unported callee. Its complete identity remains
//! unrecovered; target defaults retain the verified retail entry address.

use core::ptr;
use super::media_slot_release::MEDIA_SLOT_RELEASE_OPS;

const ARTWORK_DATABASE_WORD: usize = 0xf9c / 4;

/// Releases the artwork database, including passing a zero word to the callee.
///
/// # Safety
/// `owner` must be four-byte aligned, writable through offset 0xf9f, and its
/// artwork database word must be a valid argument for the media release seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn artwork_database_release(owner: *mut u32) {
    let ops = ptr::read_volatile(ptr::addr_of!(MEDIA_SLOT_RELEASE_OPS));
    release_with(owner, ops.media_allocation_release);
}

unsafe fn release_with(owner: *mut u32, release: unsafe extern "C" fn(*mut u8)) {
    let database_slot = owner.add(ARTWORK_DATABASE_WORD);
    release(database_slot.read() as usize as *mut u8);
    database_slot.write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::Cell;

    std::thread_local! {
        static OWNER: Cell<*mut u32> = const { Cell::new(ptr::null_mut()) };
        static EXPECTED: Cell<u32> = const { Cell::new(0) };
        static CALLS: Cell<u32> = const { Cell::new(0) };
    }

    unsafe extern "C" fn release_and_mutate(database: *mut u8) {
        EXPECTED.with(|expected| {
            assert_eq!(database as usize, expected.get() as usize);
            OWNER.with(|owner| {
                let slot = owner.get().add(ARTWORK_DATABASE_WORD);
                // The original field must still be present during release.
                assert_eq!(slot.read(), expected.get());
                slot.write(0xdead_beef);
            });
        });
        CALLS.with(|calls| calls.set(calls.get() + 1));
    }

    #[test]
    fn clears_after_release_even_for_null_and_high_bit_target_words() {
        for database in [0, 1, 0x8000_0000, u32::MAX] {
            let mut owner = [0xa5a5_a5a5u32; ARTWORK_DATABASE_WORD + 2];
            owner[ARTWORK_DATABASE_WORD] = database;
            let mut expected = owner;
            expected[ARTWORK_DATABASE_WORD] = 0;
            OWNER.with(|cell| cell.set(owner.as_mut_ptr()));
            EXPECTED.with(|cell| cell.set(database));
            CALLS.with(|cell| cell.set(0));
            unsafe { release_with(owner.as_mut_ptr(), release_and_mutate); }
            assert_eq!(owner, expected);
            CALLS.with(|cell| assert_eq!(cell.get(), 1));
            OWNER.with(|cell| cell.set(ptr::null_mut()));
        }
    }
}

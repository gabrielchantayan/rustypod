//! Tagged buffer range release — retailOS `FUN_083e41d4` at load address
//! `0x083e41d4` (40 bytes, `0x083e41d4..0x083e41fc`). Raw `osos.dec` confirms
//! the following `mov r1,#0; str r1,[r0]` at `0x083e4200` begins the next
//! function.
//!
//! The ten ARM words save the half-open range bounds from r1/r2, branch to
//! the comparison, then call `tagged_buffer_release` at `0x0827c158` for each
//! 16-byte entry in ascending address order. Raw decode finds one plain `bl`,
//! no predicated calls, and no data references. The ignored r0 is preserved
//! only as an ABI argument.
//!
//! Deliberate deviation: none; the call boundary remains the existing Rust
//! `tagged_buffer_release` port. Byte-pointer stepping explicitly preserves
//! the target's 16-byte entry stride on 64-bit host test builds.

use crate::cxx::tagged_buffer_release::tagged_buffer_release;

const TAGGED_BUFFER_SIZE: usize = 16;

type TaggedBufferRelease = unsafe extern "C" fn(*mut u8);

/// Releases every 16-byte tagged buffer in the half-open `[begin, end)` range.
///
/// `_ignored` is the retail ABI's unused r0 argument. `begin` and `end` must
/// delimit entries at the target's fixed 16-byte stride.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_buffer_range_release(
    _ignored: *mut u8,
    begin: *mut u8,
    end: *mut u8,
) {
    unsafe { tagged_buffer_range_release_with(begin, end, tagged_buffer_release) }
}

#[inline(always)]
unsafe fn tagged_buffer_range_release_with(
    mut current: *mut u8,
    end: *mut u8,
    release: TaggedBufferRelease,
) {
    unsafe {
        while current != end {
            release(current);
            current = current.add(TAGGED_BUFFER_SIZE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_BUFFERS: [AtomicUsize; 3] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    unsafe extern "C" fn record_release(buffer: *mut u8) {
        let index = RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
        RELEASED_BUFFERS[index].store(buffer as usize, Ordering::SeqCst);
    }

    fn reset_observations() {
        RELEASE_COUNT.store(0, Ordering::SeqCst);
        for buffer in &RELEASED_BUFFERS {
            buffer.store(0, Ordering::SeqCst);
        }
    }

    #[test]
    fn releases_each_target_sized_buffer_in_address_order() {
        let mut buffers = [[0u8; TAGGED_BUFFER_SIZE]; 3];
        reset_observations();

        unsafe {
            tagged_buffer_range_release_with(
                buffers.as_mut_ptr().cast(),
                buffers.as_mut_ptr().add(buffers.len()).cast(),
                record_release,
            );
        }

        assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), buffers.len());
        for (index, buffer) in buffers.iter_mut().enumerate() {
            assert_eq!(
                RELEASED_BUFFERS[index].load(Ordering::SeqCst),
                buffer.as_mut_ptr() as usize
            );
        }
    }

    #[test]
    fn empty_range_does_not_dereference_its_bounds() {
        reset_observations();

        unsafe {
            tagged_buffer_range_release_with(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                record_release,
            );
        }

        assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 0);
    }
}

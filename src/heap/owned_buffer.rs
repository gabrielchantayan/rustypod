//! `owned_buffer_destroy` — destroy a heap-allocated four-word buffer owner.
//!
//! Original: `FUN_0803a2ec` @ 0x0803a2ec (36 bytes exactly,
//! 0x0803a2ec..0x0803a310; the next independently linked body starts at
//! 0x0803a310, with no trailing literal pool). Decoding every ARM B/BL
//! immediate in `osos.dec` finds 16 direct `bl`-form call sites: 15
//! unconditional `bl` and one `blne` (@ 0x08040ca0). A separate tail `b`
//! reaches this body @ 0x08091334. The sole predicated caller proves that
//! callers sometimes gate destruction themselves; this body still has its
//! own NULL guard.
//!
//! Algorithm: NULL returns immediately. Otherwise, the owner releases its
//! non-NULL data allocation (+0x08) through `traced_free`, then always
//! releases the owner itself through the same allocator front-end.
//!
//! Deliberate deviation: the final `b traced_free` tail branch is an ordinary
//! returning Rust call. `traced_free` returns normally, so observable calls
//! and their order are unchanged.

use crate::drivers::ata_cmd::traced_free;

/// Target-layout owner allocated by the sibling factory @ 0x0803a488.
///
/// Only `data` is consumed here. The other words retain the target layout:
/// sibling code initializes word 0 to zero, stores its constructor argument
/// in word 1, and later writes word 3 after growing/copying the data.
#[repr(C)]
pub struct OwnedBuffer {
    pub length: u32,
    pub source: u32,
    pub data: *mut u8,
    pub context: u32,
}

const _: [u8; 0x08] = [0; core::mem::offset_of!(OwnedBuffer, data)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::size_of::<OwnedBuffer>()];

/// owned_buffer_destroy — original: `FUN_0803a2ec` @ 0x0803a2ec (36 bytes;
/// 15 `bl` + 1 `blne` direct call sites, plus one tail `b`).
///
/// Releases `owner.data` when it is non-NULL, then releases `owner`. The
/// pointer must be NULL or name a writable, aligned [`OwnedBuffer`] whose
/// non-NULL `data` is a live allocation from `traced_free`'s allocator
/// family. Neither pointer is cleared: matching the original, repeated calls
/// release the same allocations again.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_buffer_destroy(owner: *mut OwnedBuffer) {
    if owner.is_null() {
        return;
    }

    let data = (*owner).data;
    if !data.is_null() {
        traced_free(data);
    }
    traced_free(owner.cast());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS, TRACED_FREE_TEST_LOCK};
    use parking_lot::Mutex;

    static FREED: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_free(block: *mut u8) {
        FREED.lock().push(block as usize);
    }

    struct FreeHooksReset(TracedFreeHooks);

    impl Drop for FreeHooksReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_FREE_HOOKS), self.0);
            }
        }
    }

    fn destroy_and_record(owner: *mut OwnedBuffer) -> std::vec::Vec<usize> {
        let _global_free_guard = TRACED_FREE_TEST_LOCK.lock();
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS)) };
        let _reset = FreeHooksReset(previous);
        FREED.lock().clear();
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(TRACED_FREE_HOOKS),
                TracedFreeHooks { free: record_free, trace: None },
            );
            owned_buffer_destroy(owner);
        }
        FREED.lock().clone()
    }

    #[test]
    fn null_owner_does_not_reach_the_allocator() {
        assert!(destroy_and_record(core::ptr::null_mut()).is_empty());
    }

    #[test]
    fn null_data_releases_only_the_owner() {
        let mut owner = OwnedBuffer { length: 0, source: 0, data: core::ptr::null_mut(), context: 0 };
        assert_eq!(destroy_and_record(&mut owner), [&mut owner as *mut OwnedBuffer as usize]);
    }

    #[test]
    fn data_is_released_before_its_owner() {
        let mut data = 0u8;
        let mut owner = OwnedBuffer { length: 17, source: 0xfeed_cafe, data: &mut data, context: 0x1234_5678 };
        assert_eq!(
            destroy_and_record(&mut owner),
            [&mut data as *mut u8 as usize, &mut owner as *mut OwnedBuffer as usize],
        );
    }
}

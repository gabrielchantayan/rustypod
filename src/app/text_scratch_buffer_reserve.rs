//! Grow-only text conversion scratch buffer — FUN_080ce550 @ 0x080ce550.
//!
//! True extent: 88 bytes, ending at the independent push at 0x080ce5a8.
//! Raw A32 words contain two plain BLs and zero predicated BLs; whole-image
//! decoding also finds two plain inbound BLs, both in 0x080be330's text path.
//! Compare unsigned capacity at +0x400e4 with the requested byte count. On
//! growth, free a nonzero buffer at +0x400e8 and clear pointer then capacity;
//! allocate exactly the request with tag 4. Store the pointer even on failure,
//! return -108 on NULL, and publish capacity only on success. A NULL old
//! pointer skips both clears, so failure preserves its stale capacity.
//! Deliberate deviations: LLVM may reverse the independent clears after free;
//! exclusive state ownership makes this unobservable. Existing heap-seam
//! deviations remain unchanged. Target-width word indices preserve offsets
//! on hosts; the containing class is unnamed.

use crate::heap::veneers::{free_tag4, malloc_tag4};

const CAPACITY: usize = 0x400e4 / 4;
const BUFFER: usize = 0x400e8 / 4;

/// # Safety
/// `state` addresses at least 0x400ec writable aligned bytes. A nonzero
/// buffer word must be a live tag-4 allocation. Allocations must fit in u32.
/// The state must be exclusively owned throughout the call.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn text_scratch_buffer_reserve(state: *mut u32, required: u32) -> i32 {
    unsafe {
        if state.add(CAPACITY).read() < required {
            let old_buffer = state.add(BUFFER).read();
            if old_buffer != 0 {
                free_tag4(old_buffer as usize as *mut u8);
                state.add(BUFFER).write(0);
                state.add(CAPACITY).write(0);
            }
            let buffer = malloc_tag4(required as usize);
            state.add(BUFFER).write(buffer as usize as u32);
            if buffer.is_null() { return -108; }
            state.add(CAPACITY).write(required);
        }
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{HEAP_OPS, HeapVeneerOps, tests::mock_heap};
    use std::vec;
    use std::vec::Vec;

    static mut EVENTS: Vec<(usize, usize, usize)> = Vec::new();
    static mut RESULT: usize = 0;
    static mut ACTIVE: *mut u32 = core::ptr::null_mut();
    static mut BEFORE_ALLOC: (u32, u32) = (0, 0);

    unsafe extern "C" fn allocate(_: *mut HeapDescriptorDescriptor, size: usize, tag: usize) -> *mut u8 {
        unsafe {
            assert_eq!((ACTIVE.add(CAPACITY).read(), ACTIVE.add(BUFFER).read()), BEFORE_ALLOC);
            (*core::ptr::addr_of_mut!(EVENTS)).push((1, size, tag));
            RESULT as *mut u8
        }
    }
    unsafe extern "C" fn release(_: *mut HeapDescriptorDescriptor, buffer: *mut u8, tag: usize) {
        unsafe {
            assert_eq!(ACTIVE.add(BUFFER).read(), buffer as usize as u32);
            (*core::ptr::addr_of_mut!(EVENTS)).push((0, buffer as usize, tag));
        }
    }
    struct Restore(HeapVeneerOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { HEAP_OPS = self.0; ACTIVE = core::ptr::null_mut(); } }
    }

    #[test]
    fn unsigned_growth_and_destructive_failure_preserve_exact_state() {
        let _lock = mock_heap();
        let _restore = Restore(unsafe { HEAP_OPS });
        unsafe { HEAP_OPS.alloc = allocate; HEAP_OPS.free = release; }
        // Numeric mock pointers are never dereferenced by either heap callback.
        for (capacity, old, required, result) in [
            (0, 0, 0, 0), (8, 0x1234, 8, 0), (8, 0x1234, 7, 0),
            (u32::MAX, 0x1234, 0x8000_0000, 0),
            (8, 0x1234, 9, 0x5678), (0, 0, 1, 0x5678),
            (8, 0x1234, 9, 0), (8, 0, 9, 0),
            (0, 0, u32::MAX, 0),
        ] {
            let mut state = vec![0xa5a5_a5a5u32; BUFFER + 2];
            state[CAPACITY] = capacity;
            state[BUFFER] = old;
            let mut expected = state.clone();
            let grows = capacity < required;
            let mut events = Vec::new();
            if grows {
                if old != 0 {
                    events.push((0, old as usize, 4));
                    expected[CAPACITY] = 0;
                }
                events.push((1, required as usize, 4));
                expected[BUFFER] = result as u32;
                if result != 0 { expected[CAPACITY] = required; }
            }
            unsafe {
                ACTIVE = state.as_mut_ptr(); RESULT = result;
                BEFORE_ALLOC = (if old != 0 { 0 } else { capacity }, 0);
                (*core::ptr::addr_of_mut!(EVENTS)).clear();
                assert_eq!(text_scratch_buffer_reserve(ACTIVE, required),
                    if grows && result == 0 { -108 } else { 0 });
                assert_eq!(&*core::ptr::addr_of!(EVENTS), &events);
            }
            assert_eq!(state, expected);
        }
    }
}

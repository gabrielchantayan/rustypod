//! Image-library buffer cleanup — FUN_080d2084 @ 0x080d2084.
//! True extent [0x080d2084,0x080d20e4), 96 bytes, no literals; the next
//! entry begins with LDR at 0x080d20e4. Raw ARM-word decoding finds two
//! inbound plain BLs (0x080490fc, 0x0805e0d8), zero predicated BLs.
//! The body has four plain BLs, zero predicated BLs, and a tail unlock.
//!
//! Save and lock the mutex at +0x9d0, then free non-NULL tag-4 buffers
//! at +0x9d4, +0x9dc, +0x9d8 in that order, clearing each only after
//! its free returns. Unlock the saved mutex, not a reloaded owner field.
//! Callers invalidate these buffers after adding an image-library entry
//! and during library destruction. Buffer contents are not identified.
//!
//! Deviations: native pointer fields widen on hosts; repr(C) retains the
//! exact target offsets. Existing heap/kernel dispatch conventions apply.
//! Volatile slot accesses retain callback-visible load/store ordering;
//! Rust expresses the final tail branch as an ordinary call.

use crate::heap::veneers::free_tag4;
use crate::kernel::sync_mutex::{Mutex, mutex_lock, mutex_unlock};

/// Only the owned buffer tail is interpreted; preceding library state is opaque.
#[repr(C)]
pub struct ImageLibraryBuffers {
    pub opaque: [u8; 0x9d0],
    pub mutex: *mut Mutex,
    pub first_buffer: *mut u8,
    pub second_buffer: *mut u8,
    pub third_buffer: *mut u8,
}

/// Requires a valid library and mutex; every non-NULL buffer must be tag-4 owned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_library_buffers_clear(library: *mut ImageLibraryBuffers) {
    let mutex = core::ptr::read_volatile(core::ptr::addr_of!((*library).mutex));
    mutex_lock(mutex);
    let first = core::ptr::addr_of_mut!((*library).first_buffer);
    let buffer = first.read_volatile();
    if !buffer.is_null() {
        free_tag4(buffer);
        first.write_volatile(core::ptr::null_mut());
    }
    let third = core::ptr::addr_of_mut!((*library).third_buffer);
    let buffer = third.read_volatile();
    if !buffer.is_null() {
        free_tag4(buffer);
        third.write_volatile(core::ptr::null_mut());
    }
    let second = core::ptr::addr_of_mut!((*library).second_buffer);
    let buffer = second.read_volatile();
    if !buffer.is_null() {
        free_tag4(buffer);
        second.write_volatile(core::ptr::null_mut());
    }
    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::{HEAP_OPS, tests::mock_heap};
    use crate::heap::types::HeapDescriptorDescriptor;
    use std::vec::Vec;

    static mut ACTIVE: *mut ImageLibraryBuffers = core::ptr::null_mut();
    static LOG: parking_lot::Mutex<Vec<usize>> = parking_lot::Mutex::new(Vec::new());
    static mut REPLACE: bool = false;

    unsafe extern "C" fn observe_free(_heap: *mut HeapDescriptorDescriptor, buffer: *mut u8, tag: usize) {
        assert_eq!(tag, 4);
        let library = ACTIVE;
        let mut log = LOG.lock();
        // Each slot remains populated during its own release, but previous
        // slots have already been cleared before the next release begins.
        match buffer as usize {
            1 => {
                assert_eq!((*library).first_buffer, buffer);
                if REPLACE {
                    (*library).third_buffer = 4usize as *mut u8;
                    (*library).first_buffer = 5usize as *mut u8;
                }
            }
            3 | 4 => {
                assert!((*library).first_buffer.is_null());
                assert_eq!((*library).third_buffer, buffer);
            }
            2 => {
                assert!((*library).first_buffer.is_null());
                assert!((*library).third_buffer.is_null());
                assert_eq!((*library).second_buffer, buffer);
            }
            _ => panic!("unexpected buffer"),
        }
        log.push(buffer as usize);
    }

    #[test]
    fn clears_every_nullable_combination_in_release_order_and_is_idempotent() {
        let _guard = mock_heap();
        unsafe {
            let saved = HEAP_OPS;
            HEAP_OPS.free = observe_free;
            REPLACE = false;
            let mut mutex = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };
            for mask in 0..8 {
                let mut library = ImageLibraryBuffers {
                    opaque: [0xa5; 0x9d0], mutex: &mut mutex,
                    first_buffer: if mask & 1 != 0 { 1usize as *mut u8 } else { core::ptr::null_mut() },
                    second_buffer: if mask & 2 != 0 { 2usize as *mut u8 } else { core::ptr::null_mut() },
                    third_buffer: if mask & 4 != 0 { 3usize as *mut u8 } else { core::ptr::null_mut() },
                };
                ACTIVE = &mut library;
                LOG.lock().clear();
                image_library_buffers_clear(&mut library);
                let expected: Vec<usize> = [1, 3, 2].into_iter()
                    .filter(|&id| mask & (1 << (id - 1)) != 0).collect();
                assert_eq!(*LOG.lock(), expected);
                assert!(library.first_buffer.is_null());
                assert!(library.second_buffer.is_null());
                assert!(library.third_buffer.is_null());
                assert_eq!(library.opaque, [0xa5; 0x9d0]);
                assert_eq!(library.mutex, &mut mutex as *mut Mutex);
                image_library_buffers_clear(&mut library);
                assert_eq!(*LOG.lock(), expected);
            }
            HEAP_OPS = saved;
            ACTIVE = core::ptr::null_mut();
        }
    }

    #[test]
    fn reloads_later_slots_and_clears_callback_replacement_after_release() {
        let _guard = mock_heap();
        unsafe {
            let saved = HEAP_OPS;
            HEAP_OPS.free = observe_free;
            REPLACE = true;
            let mut mutex = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };
            let mut library = ImageLibraryBuffers {
                opaque: [0; 0x9d0], mutex: &mut mutex,
                first_buffer: 1usize as *mut u8, second_buffer: 2usize as *mut u8,
                third_buffer: 3usize as *mut u8,
            };
            ACTIVE = &mut library;
            LOG.lock().clear();
            image_library_buffers_clear(&mut library);
            assert_eq!(*LOG.lock(), [1, 4, 2]);
            assert!(library.first_buffer.is_null());
            assert!(library.second_buffer.is_null());
            assert!(library.third_buffer.is_null());
            HEAP_OPS = saved;
            REPLACE = false;
            ACTIVE = core::ptr::null_mut();
        }
    }
}

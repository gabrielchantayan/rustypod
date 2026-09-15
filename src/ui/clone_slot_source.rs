//! Clone a `plst` slot-source buffer.
//!
//! `clone_slot_source` is `FUN_080da6a0` @ `0x080da6a0`. Raw `osos.dec`
//! words establish a 60-byte extent: the `cmp r0, #0x28` at `0x080da6dc`
//! starts the next function. It has five direct inbound calls, all plain
//! `bl` (zero predicated); its body makes two plain `bl` calls.

use crate::heap::veneers::malloc_tag4;
use crate::libc::bcopy_guarded::bcopy_guarded;

#[inline(always)]
unsafe fn clone_slot_source_with(
    source: *mut u8,
    allocate: unsafe extern "C" fn(usize) -> *mut u8,
    copy: unsafe extern "C" fn(*const u8, *mut u8, i32),
) -> *mut u8 {
    if source.is_null() {
        return core::ptr::null_mut();
    }

    let byte_len = source.add(8).cast::<u32>().read();
    let clone = allocate(byte_len as usize);
    if clone.is_null() {
        return core::ptr::null_mut();
    }

    copy(source, clone, byte_len as i32);
    clone
}

/// clone_slot_source — original: `FUN_080da6a0` @ `0x080da6a0` (60 bytes).
///
/// Returns NULL for a NULL source or an allocation failure. Otherwise allocates
/// `source[2]` bytes with tag 4 and copies that many bytes from the source into
/// the allocation. `source` must point to at least 12 readable bytes; the
/// returned allocation has the raw allocator/copy routines' validity contract.
///
/// Raw decoding confirms five plain inbound `bl` calls and no predicated calls;
/// the body calls `malloc_tag4` then `bcopy_guarded`, both plain `bl`. Deliberate
/// deviation: the ARM register-save sequence is represented by Rust ABI code;
/// the two verified callee seams are called by symbol rather than their stock
/// addresses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clone_slot_source(source: *mut u8) -> *mut u8 {
    clone_slot_source_with(source, malloc_tag4, bcopy_guarded)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_CALLS: usize = 0;
    static mut COPY_CALLS: usize = 0;
    static mut ALLOC_SIZE: usize = 0;
    static mut COPY_SOURCE: *const u8 = ptr::null();
    static mut COPY_LEN: i32 = 0;
    static mut DESTINATION: [u8; 32] = [0; 32];
    static mut ALLOCATE_NULL: bool = false;

    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        ALLOC_CALLS += 1;
        ALLOC_SIZE = size;
        if ALLOCATE_NULL { ptr::null_mut() } else { core::ptr::addr_of_mut!(DESTINATION).cast() }
    }

    unsafe extern "C" fn copy(source: *const u8, destination: *mut u8, len: i32) {
        COPY_CALLS += 1;
        COPY_SOURCE = source;
        COPY_LEN = len;
        ptr::copy(source, destination, len as usize);
    }

    unsafe fn reset() {
        ALLOC_CALLS = 0;
        COPY_CALLS = 0;
        ALLOC_SIZE = 0;
        COPY_SOURCE = ptr::null();
        COPY_LEN = 0;
        DESTINATION = [0; 32];
        ALLOCATE_NULL = false;
    }

    #[test]
    fn null_source_skips_all_callees() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            reset();
            assert!(clone_slot_source_with(ptr::null_mut(), allocate, copy).is_null());
            assert_eq!(ALLOC_CALLS, 0);
            assert_eq!(COPY_CALLS, 0);
        }
    }

    #[test]
    fn allocation_failure_skips_copy() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut source = [0xabu8; 16];
        source[8..12].copy_from_slice(&12u32.to_ne_bytes());
        unsafe {
            reset();
            ALLOCATE_NULL = true;
            assert!(clone_slot_source_with(source.as_mut_ptr(), allocate, copy).is_null());
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_SIZE, 12);
            assert_eq!(COPY_CALLS, 0);
        }
    }

    #[test]
    fn copies_the_entire_source_with_its_word_length() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut source = [0u8; 16];
        source[..12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 12, 0, 0, 0]);
        unsafe {
            reset();
            let clone = clone_slot_source_with(source.as_mut_ptr(), allocate, copy);
            assert_eq!(clone, core::ptr::addr_of_mut!(DESTINATION).cast());
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_SIZE, 12);
            assert_eq!(COPY_CALLS, 1);
            assert_eq!(COPY_SOURCE, source.as_ptr());
            assert_eq!(COPY_LEN, 12);
            assert_eq!(&DESTINATION[..12], &source[..12]);
        }
    }
}

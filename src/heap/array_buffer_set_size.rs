//! `array_buffer_set_size` — `FUN_080d2cbc` @ 0x080d2cbc.
//! True extent: 92 instruction bytes, ending at the independent branch veneer
//! @ 0x080d2d18. Raw ARM words verify two outgoing plain BLs (constructor
//! @ 0x0805d170 and length setter @ 0x0805d270), two incoming plain BLs
//! @ 0x080a6364/0x080a63a0, and no predicated BLs in either direction.
//! If the requested backing size differs from the cached size, construct a
//! zero-filled MemH buffer or resize the existing one. Return -108 on creation
//! failure or propagate resize errors; update the cached size only on success.
//! Deliberate deviations: none in the algorithm. Calls use the existing Rust
//! MemH ports and their documented heap dispatch rather than retail addresses.

use crate::heap::memh_buffer_create::memh_buffer_create;
use crate::heap::memh_set_len::{memh_set_len, MemhBufferHeader};

/// Set the backing-buffer byte size of a retail array object.
///
/// # Safety
/// `array` must point to seven aligned readable/writable target-width words.
/// Word 6 must be zero or a valid MemH header pointer accepted by memh_set_len.
/// Word 4 is the cached backing size. The second ABI argument is unused.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn array_buffer_set_size(array: *mut u32, _unused: u32, size: u32) -> i32 {
    if array.add(4).read() == size {
        return 0;
    }
    let header = array.add(6).read() as usize as *mut MemhBufferHeader;
    if header.is_null() {
        let created = memh_buffer_create(size);
        array.add(6).write(created as usize as u32);
        if created.is_null() {
            return -108;
        }
    } else {
        let status = memh_set_len(header, size);
        if status != 0 {
            return status;
        }
    }
    array.add(4).write(size);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::memh_handle::MEMH_MAGIC;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::LazyLock;

    static SLAB: LazyLock<usize> = LazyLock::new(|| {
        try_map_u32_slab(hints::ARRAY_BUFFER_SET_SIZE, 0x1000)
            .expect("array buffer test requires a target-width mapping") as usize
    });

    fn header() -> *mut MemhBufferHeader {
        let header = *SLAB as *mut MemhBufferHeader;
        unsafe {
            header.write(MemhBufferHeader {
                payload: (*SLAB + 0x100) as u32,
                magic: MEMH_MAGIC,
                capacity: 16,
                length: 8,
            });
        }
        header
    }

    #[test]
    fn equal_size_skips_even_an_invalid_header() {
        let mut array = [11, 4, 2, 8, 0, 99, 1];
        assert_eq!(unsafe { array_buffer_set_size(array.as_mut_ptr(), u32::MAX, 0) }, 0);
        assert_eq!(array, [11, 4, 2, 8, 0, 99, 1]);
    }

    #[test]
    fn creation_records_header_and_size_only_on_success() {
        let _heap = mock_heap();
        let storage = header();
        let mut array = [11, 4, 2, 8, 8, 99, 0];
        set_alloc_ret(core::ptr::null_mut());
        assert_eq!(unsafe { array_buffer_set_size(array.as_mut_ptr(), 0, 12) }, -108);
        assert_eq!(array, [11, 4, 2, 8, 8, 99, 0]);
        set_alloc_ret(storage.cast());
        assert_eq!(unsafe { array_buffer_set_size(array.as_mut_ptr(), 0, 12) }, 0);
        assert_eq!(array, [11, 4, 2, 8, 12, 99, storage as usize as u32]);
        assert_eq!(unsafe { ((*storage).magic, (*storage).capacity, (*storage).length) },
                   (MEMH_MAGIC, 12, 12));
    }

    #[test]
    fn resize_commits_cached_size_and_preserves_it_on_errors() {
        let _heap = mock_heap();
        let storage = header();
        let mut array = [11, 4, 2, 8, 8, 99, storage as usize as u32];
        assert_eq!(unsafe { array_buffer_set_size(array.as_mut_ptr(), 123, 12) }, 0);
        assert_eq!(unsafe { (*storage).length }, 12);
        assert_eq!(array[4], 12);
        set_alloc_ret(core::ptr::null_mut());
        assert_eq!(unsafe { array_buffer_set_size(array.as_mut_ptr(), 0, 32) }, -108);
        assert_eq!(unsafe { ((*storage).capacity, (*storage).length) }, (16, 12));
        assert_eq!(array[4], 12);
        unsafe { (*storage).magic = 0; }
        assert_eq!(unsafe { array_buffer_set_size(array.as_mut_ptr(), 0, 0) }, -50);
        assert_eq!(array, [11, 4, 2, 8, 12, 99, storage as usize as u32]);
        unsafe { (*storage).magic = MEMH_MAGIC; }
        assert_eq!(unsafe { array_buffer_set_size(array.as_mut_ptr(), 0, 0) }, -108);
        assert_eq!(array[4], 12);
    }
}

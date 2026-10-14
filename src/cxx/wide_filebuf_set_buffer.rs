//! Wide-character file-buffer storage configuration.

use super::wide_filebuf_set_owned::wide_filebuf_set_owned;
use super::wide_filebuf_set_unbuffered::wide_filebuf_set_unbuffered;
use crate::heap::veneers::{operator_new_tag3, operator_delete_tag3};

/// retailOS `FUN_083d9a64` at `0x083d9a64`, 188 bytes, ending at the
/// independent PUSH at `0x083d9b20`. Raw aligned decoding: one incoming
/// plain BL, no incoming predicated BL; three outgoing plain BLs, one
/// BLNE, and one indirect call (MOV PC,R1) through vtable slot 13.
///
/// Invoke the virtual preflight; on success, positive capacity replaces
/// storage (allocating wrapping capacity*2 bytes if absent), updates ownership,
/// and frees the previously owned buffer. Nonpositive capacity accepts only
/// null storage and enables unbuffered mode without releasing old storage.
/// Successful calls clear all six cursor words and return the object.
/// No target behavioral deviations. Host vtables use native-width function
/// slots; object fields remain target-width words. The preflight slot is not
/// assigned a guessed concrete callee. Existing heap and flag ports are reused.
///
/// # Safety
/// `buffer` must reference at least eleven writable aligned u32 words, with
/// a valid vtable address in word 0 and callable slot 13. Owned storage must
/// be valid for tag-3 deletion; supplied storage must outlive its use.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wide_filebuf_set_buffer(
    buffer: *mut u32, storage: *mut u16, capacity: i32,
) -> *mut u32 {
    let vtable = buffer.read() as usize as *const unsafe extern "C" fn(*mut u32) -> i32;
    if vtable.add(13).read()(buffer) != 0 {
        return core::ptr::null_mut();
    }
    let owned = buffer.add(4).read() & 1 != 0;
    if capacity > 0 {
        let allocate = storage.is_null();
        let replacement = if allocate {
            operator_new_tag3((capacity as u32).wrapping_mul(2) as usize) as *mut u16
        } else { storage };
        wide_filebuf_set_owned(buffer, allocate as i32);
        if owned {
            operator_delete_tag3(buffer.add(2).read() as usize as *mut u8);
        }
        buffer.add(2).write(replacement as usize as u32);
        buffer.add(3).write(capacity as u32);
        wide_filebuf_set_unbuffered(buffer, 0);
    } else {
        if !storage.is_null() {
            return core::ptr::null_mut();
        }
        wide_filebuf_set_unbuffered(buffer, 1);
    }
    for index in [5, 6, 7, 9, 8, 10] {
        buffer.add(index).write(0);
    }
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::{HEAP_OPS, tests::mock_heap};
    use core::sync::atomic::{AtomicUsize, Ordering};
    static ALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);
    static FREED: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn preflight(buffer: *mut u32) -> i32 {
        buffer.add(1).read() as i32
    }
    unsafe extern "C" fn alloc(_: *mut crate::heap::types::HeapDescriptorDescriptor, size: usize, _: usize) -> *mut u8 {
        ALLOC_SIZE.store(size, Ordering::SeqCst);
        0x12340000usize as *mut u8
    }
    unsafe extern "C" fn free(_: *mut crate::heap::types::HeapDescriptorDescriptor, ptr: *mut u8, _: usize) {
        FREED.store(ptr as usize, Ordering::SeqCst);
    }

    #[test]
    fn rejection_modes_and_ownership_transitions() {
        let _guard = mock_heap();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::WIDE_FILEBUF_SET_BUFFER, 4096,
        ) else { return; };
        unsafe {
            let table = slab as *mut unsafe extern "C" fn(*mut u32) -> i32;
            table.add(13).write(preflight);
            let saved = HEAP_OPS;
            HEAP_OPS.alloc = alloc;
            HEAP_OPS.free = free;
            for (status, storage, capacity, flags) in [
                (7, 0, 4, 0x85), (0, 0x43210000, 0, 0x85),
                (0, 0x43210000, -1, 0x85), (0, 0, 0, 0x81),
                (0, 0, i32::MIN, 0x80), (0, 0x43210000, 3, 0x85),
                (0, 0, 3, 0x84), (0, 0, i32::MAX, 0x85),
            ] {
                let mut words = [0x55555555; 12];
                words[0] = slab as usize as u32;
                words[1] = status;
                words[2] = 0x23450000;
                words[4] = flags;
                let before = words;
                ALLOC_SIZE.store(0, Ordering::SeqCst);
                FREED.store(0, Ordering::SeqCst);
                let result = wide_filebuf_set_buffer(words.as_mut_ptr(), storage as usize as *mut u16, capacity);
                let rejected = status != 0 || (capacity <= 0 && storage != 0);
                if rejected {
                    assert!(result.is_null());
                    assert_eq!(words, before);
                } else {
                    assert_eq!(result, words.as_mut_ptr());
                    let mut expected = before;
                    if capacity > 0 {
                        expected[2] = if storage == 0 { 0x12340000 } else { storage };
                        expected[3] = capacity as u32;
                        expected[4] = (flags & !5) | u32::from(storage == 0);
                    } else { expected[4] |= 4; }
                    expected[5..11].fill(0);
                    assert_eq!(words, expected);
                }
                assert_eq!(ALLOC_SIZE.load(Ordering::SeqCst),
                    if !rejected && capacity > 0 && storage == 0 { (capacity as u32).wrapping_mul(2) as usize } else { 0 });
                assert_eq!(FREED.load(Ordering::SeqCst),
                    if !rejected && capacity > 0 && flags & 1 != 0 { before[2] as usize } else { 0 });
            }
            HEAP_OPS = saved;
        }
    }
}

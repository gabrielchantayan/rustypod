#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::cxx::string_pair_word_uninitialized_copy::cxx_string_pair_word_uninitialized_copy;
use crate::cxx::templates::{vector_size_elem12, VectorBounds};
use crate::heap::new_handler::operator_new_checked;

/// vector_copy_construct_elem20 — retailOS `FUN_083d7d20` @ 0x083d7d20.
///
/// True extent: 172 bytes, 0x083d7d20..0x083d7dcc; the literal pool at
/// 0x083d7dcc is followed by the next `movs r0, r1` entry at 0x083d7dd0.
/// Raw A32 decoding finds two inbound plain BLs (0x083e8b20 and 0x083e9574),
/// no predicated inbound BLs, and four plain body BLs: vector_size_elem12
/// twice, operator_new_checked, and cxx_string_pair_word_uninitialized_copy.
///
/// Copy-constructs a 0x14-byte record: writes its vtable word, copies the
/// source word at +4, then constructs the embedded 12-byte-element vector at
/// +8 with capacity `max(source.len(), 32)`. The source vector records are
/// copied through the existing COW-string-pair-and-word range constructor.
///
/// # Deliberate deviations
///
/// The firmware calls `vector_size_elem12` twice; this port computes the same
/// target-width `(end - begin) / 12` from raw u32 cursor words so host fixtures
/// retain the ARM layout. Host allocation uses a volatile test seam because a
/// target pointer word cannot hold a normal 64-bit allocation pointer.
///
/// # Safety
///
/// `source` must identify a readable target-layout 0x14-byte record. Unless
/// `output` is NULL, it must identify writable target-layout storage and the
/// returned allocation must hold `max(source_len, 32) * 12` bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_elem20(
    _vector: *mut u8,
    output: *mut u8,
    source: *const u8,
) {
    if output.is_null() {
        return;
    }

    output.cast::<u32>().write(0x0898_eb5c);
    output.add(4).cast::<u32>().write(source.add(4).cast::<u32>().read());
    output.add(8).cast::<u32>().write(0);
    output.add(12).cast::<u32>().write(0);
    output.add(16).cast::<u32>().write(0);

    let source_begin = source.add(8).cast::<u32>().read() as usize as *const u8;
    let source_end = source.add(12).cast::<u32>().read() as usize as *const u8;
    let source_len = source_element_count(source);
    let capacity = source_len.max(32);
    let allocation = allocate_vector_storage(capacity * 12);
    output.add(8).cast::<u32>().write(allocation as usize as u32);
    cxx_string_pair_word_uninitialized_copy(source_begin, source_end, allocation);
    let source_len = source_element_count(source);
    output.add(12).cast::<u32>().write(allocation.add(source_len * 12) as usize as u32);
    output.add(16).cast::<u32>().write(allocation.add(capacity * 12) as usize as u32);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn allocate_vector_storage(size: usize) -> *mut u8 { operator_new_checked(size) }


#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn source_element_count(source: *const u8) -> usize {
    vector_size_elem12(source.add(8).cast::<VectorBounds>()) as usize
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn source_element_count(source: *const u8) -> usize {
    let begin = source.add(8).cast::<u32>().read() as usize;
    let end = source.add(12).cast::<u32>().read() as usize;
    end.wrapping_sub(begin) / 12
}
#[cfg(not(target_os = "none"))]
static mut VECTOR_COPY_CONSTRUCT_ELEM20_ALLOCATE: unsafe extern "C" fn(usize) -> *mut u8 = operator_new_checked;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn allocate_vector_storage(size: usize) -> *mut u8 {
    core::ptr::read_volatile(ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM20_ALLOCATE))(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATION: *mut u8 = ptr::null_mut();
    static mut ALLOCATION_SIZE: usize = 0;
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 { ALLOCATION_SIZE = size; ALLOCATION }

    #[test]
    fn constructs_target_record_with_minimum_vector_capacity() {
        let Some(slab) = try_map_u32_slab(hints::VECTOR_COPY_CONSTRUCT_ELEM20, 0x1000) else { return; };
        let _lock = LOCK.lock();
        unsafe {
            slab.write_bytes(0, 0x1000);
            let source = slab.add(0x100);
            let output = slab.add(0x200);
            let payload = slab.add(0x300);
            ALLOCATION = slab.add(0x500);
            source.add(4).cast::<u32>().write(0x1122_3344);
            source.add(8).cast::<u32>().write(payload as usize as u32);
            source.add(12).cast::<u32>().write(payload.add(24) as usize as u32);
            for i in 0..6 { payload.add(i * 4).cast::<u32>().write((i + 1) as u32); }
            let old = ptr::read_volatile(ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM20_ALLOCATE));
            VECTOR_COPY_CONSTRUCT_ELEM20_ALLOCATE = allocate;
            vector_copy_construct_elem20(ptr::null_mut(), output, source);
            VECTOR_COPY_CONSTRUCT_ELEM20_ALLOCATE = old;
            assert_eq!(ALLOCATION_SIZE, 32 * 12);
            assert_eq!(output.cast::<u32>().read(), 0x0898_eb5c);
            assert_eq!(output.add(4).cast::<u32>().read(), 0x1122_3344);
            assert_eq!(output.add(8).cast::<u32>().read(), ALLOCATION as usize as u32);
            assert_eq!(output.add(12).cast::<u32>().read(), ALLOCATION.add(24) as usize as u32);
            assert_eq!(output.add(16).cast::<u32>().read(), ALLOCATION.add(32 * 12) as usize as u32);
            for i in 0..6 { assert_eq!(ALLOCATION.add(i * 4).cast::<u32>().read(), (i + 1) as u32); }
        }
    }

    #[test]
    fn null_output_does_not_read_source_or_allocate() {
        unsafe { vector_copy_construct_elem20(ptr::null_mut(), ptr::null_mut(), 1usize as *const u8) };
    }
}

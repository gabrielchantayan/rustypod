#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::cxx::string_object::{copy_construct_op, StringObject};
use crate::cxx::templates::vector_copy_range_u8;
use crate::heap::new_handler::operator_new_checked;

/// vector_copy_construct_elem32 — retailOS `FUN_083d7f2c` @ 0x083d7f2c.
///
/// True extent: 192 bytes, 0x083d7f2c..0x083d7fec; the `mov r0, r1` at
/// 0x083d7fec opens the next function. Raw A32 words contain three plain BLs
/// (0x083d7f44 -> string_object_copy_construct, 0x083d7f98 ->
/// operator_new_checked, 0x083d7fac -> thunk_FUN_083e8ecc) and no predicated
/// BLs. Ghidra missed the veneer call and reported only two.
///
/// Copy-constructs a 0x20-byte record: its target-width StringObject at +0,
/// word at +8, then an embedded byte vector at +0x0c. The vector allocation is
/// at least 0x20 bytes, copied through the byte-range veneer, and its end and
/// capacity cursors are rebuilt. The two bytes at +0x18/+0x19 and word +0x1c
/// are copied afterwards.
///
/// # Deliberate deviations
///
/// The original directly BLs all three callees. The StringObject constructor
/// retains its existing volatile test seam; host-only allocation also uses a
/// seam because target-width pointer fields cannot hold ordinary 64-bit host
/// pointers. Target builds call `operator_new_checked` directly. The existing
/// byte-range port replaces the four-byte veneer with its target body.
///
/// # Safety
/// `source` must identify a readable target-layout 0x20-byte record. Unless
/// `output` is NULL, it must identify writable target-layout storage and the
/// returned allocation must hold `max(source_end - source_begin, 0x20)` bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vector_copy_construct_elem32(
    _vector: *mut u8,
    output: *mut u8,
    source: *const u8,
) {
    if output.is_null() {
        return;
    }

    (copy_construct_op())(output.cast::<StringObject>(), source.cast::<StringObject>());
    output.add(8).cast::<u32>().write(source.add(8).cast::<u32>().read());
    output.add(12).cast::<u32>().write(0);
    output.add(16).cast::<u32>().write(0);
    output.add(20).cast::<u32>().write(0);

    let source_begin = source.add(12).cast::<u32>().read() as usize as *const u8;
    let source_end = source.add(16).cast::<u32>().read() as usize as *const u8;
    let source_len = source_end.offset_from(source_begin) as usize;
    let capacity = source_len.max(0x20);
    let allocation = allocate_vector_storage(capacity);
    output.add(12).cast::<u32>().write(allocation as usize as u32);
    vector_copy_range_u8(source_begin, source_end, allocation);
    output.add(16).cast::<u32>().write(allocation.add(source_len) as usize as u32);
    output.add(20).cast::<u32>().write(allocation.add(capacity) as usize as u32);
    output.add(24).write(source.add(24).read());
    output.add(25).write(source.add(25).read());
    output.add(28).cast::<u32>().write(source.add(28).cast::<u32>().read());
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn allocate_vector_storage(size: usize) -> *mut u8 {
    operator_new_checked(size)
}

#[cfg(not(target_os = "none"))]
static mut VECTOR_COPY_CONSTRUCT_ELEM32_ALLOCATE: unsafe extern "C" fn(usize) -> *mut u8 = operator_new_checked;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn allocate_vector_storage(size: usize) -> *mut u8 {
    core::ptr::read_volatile(ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM32_ALLOCATE))(size)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_COPY_CONSTRUCT;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut COPIED: (*mut u8, *const u8) = (ptr::null_mut(), ptr::null());
    static mut ALLOCATION: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn copy_string(destination: *mut StringObject, source: *const StringObject) -> *mut StringObject {
        COPIED = (destination.cast(), source.cast());
        destination
    }

    unsafe extern "C" fn allocate(_size: usize) -> *mut u8 { ALLOCATION }

    #[test]
    fn copies_target_width_record_and_uses_minimum_capacity() {
        let Some(slab) = try_map_u32_slab(hints::VECTOR_COPY_CONSTRUCT_ELEM32, 0x1000) else { return; };
        let _lock = LOCK.lock();
        unsafe {
            slab.write_bytes(0, 0x1000);
            let source = slab.add(0x100);
            let output = slab.add(0x200);
            let payload = slab.add(0x300);
            let allocation = slab.add(0x400);
            source.add(12).cast::<u32>().write(payload as usize as u32);
            source.add(16).cast::<u32>().write(payload.add(3) as usize as u32);
            payload.copy_from_nonoverlapping([0x41, 0x42, 0x43].as_ptr(), 3);
            source.add(8).cast::<u32>().write(0x1122_3344);
            source.add(24).write(7); source.add(25).write(9); source.add(28).cast::<u32>().write(0xaabb_ccdd);
            ALLOCATION = allocation;
            let old_copy = core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_COPY_CONSTRUCT));
            let old_allocate = core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_COPY_CONSTRUCT_ELEM32_ALLOCATE));
            STRING_OBJECT_COPY_CONSTRUCT = copy_string;
            VECTOR_COPY_CONSTRUCT_ELEM32_ALLOCATE = allocate;
            vector_copy_construct_elem32(ptr::null_mut(), output, source);
            STRING_OBJECT_COPY_CONSTRUCT = old_copy;
            VECTOR_COPY_CONSTRUCT_ELEM32_ALLOCATE = old_allocate;
            assert_eq!(COPIED, (output, source as *const u8));
            assert_eq!(output.add(8).cast::<u32>().read(), 0x1122_3344);
            assert_eq!(output.add(12).cast::<u32>().read(), allocation as usize as u32);
            assert_eq!(output.add(16).cast::<u32>().read(), allocation.add(3) as usize as u32);
            assert_eq!(output.add(20).cast::<u32>().read(), allocation.add(0x20) as usize as u32);
            assert_eq!(core::slice::from_raw_parts(allocation, 3), &[0x41, 0x42, 0x43]);
            assert_eq!((output.add(24).read(), output.add(25).read(), output.add(28).cast::<u32>().read()), (7, 9, 0xaabb_ccdd));
        }
    }

    #[test]
    fn null_output_skips_every_callee() {
        unsafe { vector_copy_construct_elem32(ptr::null_mut(), ptr::null_mut(), 1usize as *const u8) };
    }
}

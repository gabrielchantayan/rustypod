//! `dual_pool_screen_reserve_record` — `FUN_083dc9b0` @ `0x083dc9b0`.
//! True extent: 184 bytes through pop at 0x083dca64; the next function starts
//! at 0x083dca68. Raw A32 decoding finds two outbound unconditional BLs to
//! checked new (0x08266c70), no predicated BLs, and one inbound unconditional
//! BL at 0x0812d884. Pops the first-word-threaded free list, otherwise bumps
//! by 36 bytes. Exhaustion allocates a 12-byte chunk and an untouched arena:
//! one element for nonzero `single`, otherwise initially 32, growing by
//! max(old + 32, old + old/2 + old/8), with wrapping u32 arithmetic.
//! Deviation: explicitly returns the acquired pointer, preserving the stock
//! r0 consumed by the constructor despite Ghidra's incorrect void signature.

use super::dual_pool_screen::PoolHeader;
use crate::heap::new_handler::operator_new_checked;

#[repr(C)]
struct Chunk { previous: u32, capacity: u32, elements: u32 }

/// # Safety
/// Pool and its target-width pointers must be valid writable aligned storage.
/// Checked new must succeed; like retailOS there is no allocation failure guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dual_pool_screen_reserve_record(pool: *mut PoolHeader, single: u32) -> *mut u32 {
    if (*pool).free_list != 0 {
        let element = (*pool).free_list as usize as *mut u32;
        (*pool).free_list = element.read();
        return element;
    }
    if (*pool).cursor == (*pool).limit {
        let capacity = if single != 0 { 1 } else if (*pool).chunk_list == 0 { 32 } else {
            let old = (*((*pool).chunk_list as usize as *const Chunk)).capacity;
            core::cmp::max(old.wrapping_add(32), old.wrapping_add(old >> 1).wrapping_add(old >> 3))
        };
        let chunk = operator_new_checked(12).cast::<Chunk>();
        let bytes = capacity.wrapping_mul(36);
        let elements = operator_new_checked(bytes as usize) as usize as u32;
        (*chunk).elements = elements;
        (*chunk).previous = (*pool).chunk_list;
        (*chunk).capacity = capacity;
        (*pool).chunk_list = chunk as usize as u32;
        (*pool).cursor = elements;
        (*pool).limit = elements.wrapping_add(bytes);
    }
    let element = (*pool).cursor;
    (*pool).cursor = element.wrapping_add(36);
    element as usize as *mut u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    use core::ptr;
    static mut BASE: *mut u8 = ptr::null_mut();
    static mut CALL: usize = 0;
    static mut SIZES: [usize; 8] = [0; 8];
    unsafe extern "C" fn allocate(_: *mut HeapDescriptorDescriptor, size: usize, _: usize) -> *mut u8 {
        let index = CALL;
        CALL += 1;
        SIZES[index] = size;
        BASE.add(index * 0x1000)
    }
    #[test]
    fn free_bump_single_and_growth_preserve_elements_and_metadata() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::DUAL_POOL_SCREEN_RESERVE_RECORD, 0x10000) else {
            note_missing_u32_fixture("app/dual_pool_screen_reserve_record"); return;
        };
        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x10000);
            BASE = slab; CALL = 0; SIZES = [0; 8];
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = allocate;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            let mut pool = PoolHeader { chunk_list: 0, free_list: 0, cursor: 0, limit: 0, sentinel: 7, reserved: 9 };
            let first = dual_pool_screen_reserve_record(&mut pool, 7);
            assert_eq!(first.cast::<u8>(), slab.add(0x1000));
            assert_eq!(SIZES[..2], [12, 36]);
            assert_eq!(core::slice::from_raw_parts(first, 9), &[0xa5a5_a5a5; 9]);
            first.write(slab.add(0x1100) as usize as u32);
            pool.free_list = first as usize as u32;
            let cursor = pool.cursor;
            assert_eq!(dual_pool_screen_reserve_record(&mut pool, 0), first);
            assert_eq!(pool.free_list, slab.add(0x1100) as usize as u32);
            assert_eq!(pool.cursor, cursor);
            assert_eq!(CALL, 2);
            pool.free_list = 0;
            dual_pool_screen_reserve_record(&mut pool, 0);
            assert_eq!(SIZES[2..4], [12, 33 * 36]);
            let next = pool.cursor;
            assert_eq!(dual_pool_screen_reserve_record(&mut pool, 1) as usize as u32, next);
            assert_eq!(pool.cursor, next + 36);
            assert_eq!(CALL, 4);
            pool.cursor = pool.limit;
            dual_pool_screen_reserve_record(&mut pool, 0);
            assert_eq!(SIZES[4..6], [12, 65 * 36]);
            pool.cursor = pool.limit;
            dual_pool_screen_reserve_record(&mut pool, 0);
            assert_eq!(SIZES[6..8], [12, 105 * 36]);
            let chunk = pool.chunk_list as usize as *const Chunk;
            assert_eq!((*chunk).previous, slab.add(0x4000) as usize as u32);
            assert_eq!((*chunk).capacity, 105);
            assert_eq!((pool.sentinel, pool.reserved), (7, 9));
        }
    }
}

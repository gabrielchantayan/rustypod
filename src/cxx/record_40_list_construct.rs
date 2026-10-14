//! Record-40 list constructor — `FUN_083dc968` @ `0x083dc968`.
//!
//! Raw extent [0x083dc968, 0x083dc9b0): 72 bytes, ending in pop {r4,pc};
//! the next function starts with push {r4-r6,lr}. One outgoing plain BL at
//! 0x083dc994 calls the ported node-pool acquire @ 0x083dc7e4; no predicated
//! BLs. Whole-image decoding finds one incoming plain BL at 0x081a8b94,
//! no predicated incoming BLs. Clear the six list words, acquire a single
//! 48-byte sentinel, self-link its next/previous words, and return the list.
//!
//! Deliberate deviations: none. The caller's unused r1 is omitted; all stored
//! pointers remain target-width u32 words. Sentinel payload stays untouched.

use super::record_40_list_node_pool_acquire::{record_40_list_node_pool_acquire, Record40ListNodePool};
use core::ptr::addr_of_mut;

#[repr(C)]
pub struct Record40List {
    pub pool: Record40ListNodePool,
    pub sentinel: u32,
    pub count: u32,
}

const _: [u8; 24] = [0; core::mem::size_of::<Record40List>()];
const _: [u8; 16] = [0; core::mem::offset_of!(Record40List, sentinel)];

/// # Safety
/// `list` must be aligned writable storage for six words. The configured heap
/// must provide valid writable chunks and nodes whose addresses fit in u32.
/// Existing allocations are not released; this initializes unconstructed storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_40_list_construct(list: *mut Record40List) -> *mut Record40List {
    addr_of_mut!((*list).pool).write(Record40ListNodePool::default());
    addr_of_mut!((*list).sentinel).write(0);
    addr_of_mut!((*list).count).write(0);
    let sentinel = record_40_list_node_pool_acquire(addr_of_mut!((*list).pool), 1);
    let word = sentinel as usize as u32;
    addr_of_mut!((*list).sentinel).write(word);
    addr_of_mut!((*sentinel).next).write(word);
    addr_of_mut!((*sentinel).previous).write(word);
    list
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    static mut NEXT: *mut u8 = ptr::null_mut();
    unsafe extern "C" fn slab_alloc(_: *mut HeapDescriptorDescriptor, size: usize, _: usize) -> *mut u8 {
        let result = NEXT;
        NEXT = NEXT.add((size + 3) & !3);
        result
    }

    #[test]
    fn dirty_or_zero_storage_becomes_empty_ring_without_touching_payload_or_neighbors() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RECORD_40_LIST_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture("cxx/record_40_list_construct");
            return;
        };
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = slab_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            for initial in [0u8, 0xa5, 0xff] {
                slab.write_bytes(0x69, 0x1000);
                let list = slab.add(4).cast::<Record40List>();
                list.cast::<u8>().write_bytes(initial, 24);
                NEXT = slab.add(0x100);
                assert_eq!(record_40_list_construct(list), list);
                let node = slab.add(0x10c) as usize as u32;
                assert_eq!(core::slice::from_raw_parts(list.cast::<u32>(), 6),
                    &[slab.add(0x100) as usize as u32, 0, node + 48, node + 48, node, 0]);
                assert_eq!(core::slice::from_raw_parts(slab.add(0x100).cast::<u32>(), 5),
                    &[0, 1, node, node, node]);
                assert_eq!(core::slice::from_raw_parts(slab.add(0x114).cast::<u32>(), 10), &[0x6969_6969; 10]);
                assert_eq!(slab.cast::<u32>().read(), 0x6969_6969);
                assert_eq!(slab.add(28).cast::<u32>().read(), 0x6969_6969);
                let next = NEXT;
                assert_eq!(next, slab.add(0x13c));
                assert_eq!(next.cast::<u32>().read(), 0x6969_6969);
            }
        }
    }
}

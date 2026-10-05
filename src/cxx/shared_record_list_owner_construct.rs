//! Shared-record list owner constructor — `FUN_081a8b74` @ `0x081a8b74`.
//!
//! Raw extent [0x081a8b74,0x081a8bdc): 104 bytes, ending in pop {r3-r5,pc}.
//! The next two words are distinct tail-branch functions. Whole-image word
//! decoding finds two incoming plain BLs (0x081f14b4, 0x081f7498), no predicated
//! incoming BLs; this body contains five plain BLs and no predicated BLs.
//! Clear the shared handle and three-word header; construct a pooled list with
//! one self-linked 48-byte sentinel and a recursive mutex; set the trailing
//! marker to -1, set header bit 26, self-link the header, and assign the source
//! shared handle. Return the original owner. No NULL guard or cleanup on failure.
//!
//! Deliberate deviations: inline the verified three zero stores at 0x0814d8d0
//! and the list-constructor stores at 0x083dc968, reusing its ported node pool.
//! Omit the unused stack-word address passed in r1 to that list constructor.
//! Native shared-handle pointers widen on hosts; repr(C) keeps members disjoint.
//! Ring and pool links retain target-width words and require low-address storage.
//! The existing recursive-mutex port supplies its documented host model; initial
//! scratch r2/r3 are immaterial after mutex attribute initialization.

use super::record_40_list_node_pool_acquire::{record_40_list_node_pool_acquire, Record40ListNodePool};
use super::recursive_mutex::cxx_recursive_mutex_construct;
use super::shared_cell::{shared_cell_construct_tertiary, shared_cell_assign_direct_secondary, SharedCell};
use core::ptr::{addr_of_mut, null_mut};

#[repr(C)]
pub struct SharedRecordListOwner {
    pub handle: *mut SharedCell,
    pub header: [u32; 3],
    pub pool: Record40ListNodePool,
    pub sentinel: u32,
    pub count: u32,
    pub mutex: [u32; 7],
    pub marker: u32,
}

/// # Safety
/// `owner` must be writable, aligned, and fit in a u32 address. `source` must
/// point to a valid shared-cell slot (aliasing the owner's slot is permitted).
/// The configured heap must provide writable low-address chunks and nodes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_record_list_owner_construct(
    owner: *mut SharedRecordListOwner,
    source: *mut *mut SharedCell,
) -> *mut SharedRecordListOwner {
    shared_cell_construct_tertiary(addr_of_mut!((*owner).handle), null_mut());
    addr_of_mut!((*owner).header).write([0; 3]);
    addr_of_mut!((*owner).pool).write(Record40ListNodePool::default());
    addr_of_mut!((*owner).sentinel).write(0);
    addr_of_mut!((*owner).count).write(0);
    let sentinel = record_40_list_node_pool_acquire(addr_of_mut!((*owner).pool), 1);
    let sentinel_word = sentinel as usize as u32;
    addr_of_mut!((*owner).sentinel).write(sentinel_word);
    addr_of_mut!((*sentinel).next).write(sentinel_word);
    addr_of_mut!((*sentinel).previous).write(sentinel_word);
    cxx_recursive_mutex_construct(addr_of_mut!((*owner).mutex).cast(), 0, 0, 0);
    addr_of_mut!((*owner).marker).write(u32::MAX);
    let header_word = addr_of_mut!((*owner).header) as usize as u32;
    (*owner).header = [0x0400_0000, header_word, header_word];
    shared_cell_assign_direct_secondary(addr_of_mut!((*owner).handle), source);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    use core::ptr;

    static mut NEXT: *mut u8 = ptr::null_mut();
    unsafe extern "C" fn slab_alloc(_: *mut HeapDescriptorDescriptor, size: usize, _: usize) -> *mut u8 {
        let result = NEXT;
        NEXT = NEXT.add((size + 3) & !3);
        result
    }

    #[test]
    fn initializes_dirty_storage_retains_source_and_handles_empty_or_aliasing_source() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::SHARED_RECORD_LIST_OWNER_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture("cxx/shared_record_list_owner_construct");
            return;
        };
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = slab_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            for mode in 0..4 {
                slab.write_bytes(0xa5, 0x1000);
                NEXT = slab.add(0x100);
                let owner = slab.add(8).cast::<SharedRecordListOwner>();
                let mut cell = SharedCell { value: 0, refcount: if mode == 3 { i32::MAX } else { 7 } };
                let mut source = if mode == 0 { null_mut() } else { addr_of_mut!(cell) };
                let slot = if mode == 2 { addr_of_mut!((*owner).handle) } else { addr_of_mut!(source) };
                assert_eq!(shared_record_list_owner_construct(owner, slot), owner);
                assert_eq!((*owner).handle, if mode == 2 { null_mut() } else { source });
                assert_eq!(cell.refcount, match mode { 1 => 8, 3 => i32::MIN, _ => 7 });
                let header = addr_of_mut!((*owner).header) as usize as u32;
                assert_eq!((*owner).header, [0x0400_0000, header, header]);
                let node = slab.add(0x10c) as usize as u32;
                assert_eq!((*owner).pool.chunks, slab.add(0x100) as usize as u32);
                assert_eq!((*owner).pool.free, 0);
                assert_eq!(((*owner).pool.next, (*owner).pool.end), (node + 48, node + 48));
                assert_eq!(((*owner).sentinel, (*owner).count), (node, 0));
                assert_eq!(core::slice::from_raw_parts(slab.add(0x100).cast::<u32>(), 5),
                    &[0, 1, node, node, node]);
                assert_eq!(slab.add(0x114).cast::<u32>().read(), 0xa5a5_a5a5);
                assert_eq!((*owner).mutex[0], super::super::mutex_settype_init::MUTEX_LIVE_MAGIC);
                assert_eq!((*owner).mutex[6], 0);
                assert_eq!((*owner).marker, u32::MAX);
                assert_eq!(slab.cast::<u32>().read(), 0xa5a5_a5a5);
                assert_eq!(slab.add(8 + core::mem::size_of::<SharedRecordListOwner>()).cast::<u32>().read(), 0xa5a5_a5a5);
            }
        }
    }
}

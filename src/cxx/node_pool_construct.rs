//! Initialize a C++ node-pool owner and acquire its first red-black-tree node.
//!
//! `cxx_node_pool_construct` — retailOS `FUN_083dbe5c` @ **0x083dbe5c**,
//! **88 bytes** (`0x083dbe5c..0x083dbeaf`; the `push {r3,lr}` at
//! `0x083dbeb0` begins the next real function). Raw A32 decoding finds one
//! unconditional plain body `bl`, to `cxx_node_pool_acquire` at `0x083be9e8`,
//! and zero predicated `bl` instructions. Full-image raw A32 branch decoding
//! finds two inbound unconditional plain `bl` sites and no predicated inbound
//! `bl` sites.
//!
//! # Algorithm
//!
//! Clear the owner control words and flags, retain the supplied one-byte kind
//! at `+0x19`, acquire a 20-byte node from its embedded pool, and initialize
//! the node as a self-linked empty list head (`+0x08` and `+0x0c`) with a zero
//! payload word at `+0x04`.
//!
//! # Deliberate deviation
//!
//! The retail acquisition helper is now called directly. The retail register
//! saves and `mov r0, r4` return are otherwise dead traffic; the returned owner
//! pointer and ordered target-width stores are preserved.

use super::cxx_node_pool_acquire::{cxx_node_pool_acquire, CxxNodePool};

const FIRST_NODE_OFFSET: usize = 0x10;
const KIND_OFFSET: usize = 0x19;
const NODE_PAYLOAD_OFFSET: usize = 0x04;
const NODE_PREVIOUS_OFFSET: usize = 0x08;
const NODE_NEXT_OFFSET: usize = 0x0c;

/// Initializes `owner` and returns it after acquiring and linking its first node.
///
/// # Safety
///
/// `owner` must name writable target-layout storage through `+0x19`; its
/// embedded pool must satisfy the unguarded `0x083be9e8` acquisition contract,
/// which returns a writable 20-byte node.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_node_pool_construct(owner: *mut u8, kind: *const u8) -> *mut u8 {
    owner.cast::<u32>().write(0);
    owner.add(0x10).cast::<u32>().write(0);
    owner.add(0x14).cast::<u32>().write(0);
    owner.add(0x18).write(0);
    owner.add(KIND_OFFSET).write(kind.read());
    owner.add(0x0c).cast::<u32>().write(0);
    owner.add(0x08).cast::<u32>().write(0);
    owner.add(0x04).cast::<u32>().write(0);

    let node = cxx_node_pool_acquire(owner.cast::<CxxNodePool>()).cast::<u8>();
    owner.add(FIRST_NODE_OFFSET).cast::<u32>().write(node as usize as u32);
    node.add(NODE_PAYLOAD_OFFSET).cast::<u32>().write(0);
    node.add(NODE_PREVIOUS_OFFSET).cast::<u32>().write(node as usize as u32);
    node.add(NODE_NEXT_OFFSET).cast::<u32>().write(node as usize as u32);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATIONS: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut ALLOCATION_CURSOR: usize = 0;

    unsafe extern "C" fn pool_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        _size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let index = ALLOCATION_CURSOR;
        ALLOCATION_CURSOR += 1;
        ptr::addr_of!(ALLOCATIONS).cast::<*mut u8>().add(index).read()
    }
    #[test]
    fn clears_owner_and_self_links_the_acquired_node() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_NODE_POOL_CONSTRUCT, 0x1000) else {
            return;
        };
        unsafe {
            let owner = slab.add(0x100);
            let node = slab.add(0x200);
            owner.write_bytes(0xa5, 0x20);
            node.write_bytes(0x5a, 0x14);
            ptr::addr_of_mut!(ALLOCATIONS).write([slab.add(0x300), node]);
            ALLOCATION_CURSOR = 0;
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let kind = 0x7bu8;
            assert_eq!(cxx_node_pool_construct(owner, &kind), owner);
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!(owner.cast::<u32>().read(), slab.add(0x300) as usize as u32);
            assert_eq!(owner.add(4).cast::<u32>().read(), 0);
            assert_eq!(owner.add(8).cast::<u32>().read(), node.add(0x14) as usize as u32);
            assert_eq!(owner.add(12).cast::<u32>().read(), node.add(32 * 0x14) as usize as u32);
            assert_eq!(owner.add(FIRST_NODE_OFFSET).cast::<u32>().read(), node as usize as u32);
            assert_eq!(owner.add(0x14).cast::<u32>().read(), 0);
            assert_eq!(owner.add(0x18).read(), 0);
            assert_eq!(owner.add(KIND_OFFSET).read(), kind);
            assert_eq!(node.add(NODE_PAYLOAD_OFFSET).cast::<u32>().read(), 0);
            assert_eq!(node.add(NODE_PREVIOUS_OFFSET).cast::<u32>().read(), node as usize as u32);
            assert_eq!(node.add(NODE_NEXT_OFFSET).cast::<u32>().read(), node as usize as u32);
        }
    }
}

//! Initialize a C++ node-pool owner and acquire its first list node.
//!
//! `cxx_node_pool_construct` — retailOS `FUN_083dbe5c` @ **0x083dbe5c**,
//! **88 bytes** (`0x083dbe5c..0x083dbeaf`; the `push {r3,lr}` at
//! `0x083dbeb0` begins the next real function). Raw A32 decoding finds one
//! unconditional plain body `bl`, to the still-retail node-pool acquisition
//! helper at `0x083be9e8`, and zero predicated `bl` instructions. Full-image
//! raw A32 branch decoding finds two inbound unconditional plain `bl` sites
//! and no predicated inbound `bl` sites.
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
//! The port calls the unported acquisition helper through its verified load
//! address on target and a volatile host seam in tests. The retail register
//! saves and `mov r0, r4` return are otherwise dead traffic; the returned
//! owner pointer and ordered target-width stores are preserved.

const NODE_POOL_ACQUIRE_ADDRESS: usize = 0x083b_e9e8;
const FIRST_NODE_OFFSET: usize = 0x10;
const KIND_OFFSET: usize = 0x19;
const NODE_PAYLOAD_OFFSET: usize = 0x04;
const NODE_PREVIOUS_OFFSET: usize = 0x08;
const NODE_NEXT_OFFSET: usize = 0x0c;

type NodePoolAcquire = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn node_pool_acquire(owner: *mut u8) -> *mut u8 {
    let acquire: NodePoolAcquire = core::mem::transmute(NODE_POOL_ACQUIRE_ADDRESS);
    acquire(owner)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_node_pool_acquire(_: *mut u8) -> *mut u8 {
    panic!("install cxx node-pool acquisition host seam")
}

/// Host replacement for the still-retail node-pool acquisition helper.
#[cfg(not(target_os = "none"))]
pub static mut CXX_NODE_POOL_ACQUIRE: NodePoolAcquire = missing_node_pool_acquire;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn node_pool_acquire(owner: *mut u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(CXX_NODE_POOL_ACQUIRE))(owner)
}

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

    let node = node_pool_acquire(owner);
    owner.add(FIRST_NODE_OFFSET).cast::<u32>().write(node as usize as u32);
    node.add(NODE_PAYLOAD_OFFSET).cast::<u32>().write(0);
    node.add(NODE_PREVIOUS_OFFSET).cast::<u32>().write(node as usize as u32);
    node.add(NODE_NEXT_OFFSET).cast::<u32>().write(node as usize as u32);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ACQUIRE_OWNER: *mut u8 = ptr::null_mut();
    static mut ACQUIRE_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn acquire(owner: *mut u8) -> *mut u8 {
        ACQUIRE_OWNER = owner;
        ACQUIRE_RESULT
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
            let mut seam = ptr::read_volatile(ptr::addr_of_mut!(CXX_NODE_POOL_ACQUIRE));
            let original = seam;
            seam = acquire;
            ptr::addr_of_mut!(CXX_NODE_POOL_ACQUIRE).write(seam);
            ACQUIRE_OWNER = ptr::null_mut();
            ACQUIRE_RESULT = node;

            let kind = 0x7bu8;
            assert_eq!(cxx_node_pool_construct(owner, &kind), owner);
            assert_eq!(ACQUIRE_OWNER, owner);
            assert_eq!(owner.cast::<u32>().read(), 0);
            assert_eq!(owner.add(4).cast::<u32>().read(), 0);
            assert_eq!(owner.add(8).cast::<u32>().read(), 0);
            assert_eq!(owner.add(12).cast::<u32>().read(), 0);
            assert_eq!(owner.add(FIRST_NODE_OFFSET).cast::<u32>().read(), node as usize as u32);
            assert_eq!(owner.add(0x14).cast::<u32>().read(), 0);
            assert_eq!(owner.add(0x18).read(), 0);
            assert_eq!(owner.add(KIND_OFFSET).read(), kind);
            assert_eq!(node.add(NODE_PAYLOAD_OFFSET).cast::<u32>().read(), 0);
            assert_eq!(node.add(NODE_PREVIOUS_OFFSET).cast::<u32>().read(), node as usize as u32);
            assert_eq!(node.add(NODE_NEXT_OFFSET).cast::<u32>().read(), node as usize as u32);
            ptr::addr_of_mut!(CXX_NODE_POOL_ACQUIRE).write(original);
        }
    }
}

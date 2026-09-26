//! `kinded_node_pool_construct` — retailOS `FUN_083db704` @ `0x083db704`.
//!
//! Raw `osos.dec` establishes the true 88-byte A32 extent from `push
//! {r4-r6,lr}` at `0x083db704` through `pop {r4-r6,pc}` at `0x083db758`;
//! `0x083db75c` starts the next separately linked function. The body has one
//! unconditional plain `bl`, to the unported node-pool acquisition helper at
//! `0x083c597c`, and no predicated `bl` instructions. Whole-image decoding
//! finds two inbound unconditional plain `bl` sites (`0x082ac9d8` and
//! `0x082ac9f8`) and no predicated inbound calls.
//!
//! Clears the owner control words and flags, stores the supplied kind byte at
//! `+0x19`, acquires a node from the embedded pool, and makes it an empty
//! self-linked list sentinel with a zero payload word.
//!
//! Deliberate deviation: target builds call the verified but unported
//! acquisition helper address; host tests replace it through a volatile seam.
//! The target's dead register traffic is omitted while target-width pointer
//! fields and the initialization result are preserved.

const NODE_POOL_ACQUIRE_ADDRESS: usize = 0x083c_597c;
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
    panic!("install kinded node-pool acquisition host seam")
}

/// Host replacement for the still-retail node-pool acquisition helper.
#[cfg(not(target_os = "none"))]
pub static mut KINDED_NODE_POOL_ACQUIRE: NodePoolAcquire = missing_node_pool_acquire;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn node_pool_acquire(owner: *mut u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(KINDED_NODE_POOL_ACQUIRE))(owner)
}

/// Initializes `owner` and returns it after acquiring and linking its first node.
///
/// # Safety
///
/// `owner` must name writable target-layout storage through `+0x19`; the
/// embedded pool must meet `0x083c597c`'s unguarded acquisition contract,
/// returning a writable node with words through `+0x0c`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.kinded_node_pool_construct")]
#[inline(never)]
pub unsafe extern "C" fn kinded_node_pool_construct(owner: *mut u8, kind: *const u8) -> *mut u8 {
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
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

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
        let Some(slab) = try_map_u32_slab(hints::KINDED_NODE_POOL_CONSTRUCT, 0x1000) else {
            return;
        };
        unsafe {
            let owner = slab.add(0x100);
            let node = slab.add(0x200);
            owner.write_bytes(0xa5, 0x20);
            node.write_bytes(0x5a, 0x14);
            let original = ptr::read_volatile(ptr::addr_of!(KINDED_NODE_POOL_ACQUIRE));
            ptr::addr_of_mut!(KINDED_NODE_POOL_ACQUIRE).write(acquire);
            ACQUIRE_OWNER = ptr::null_mut();
            ACQUIRE_RESULT = node;

            let kind = 0x7bu8;
            assert_eq!(kinded_node_pool_construct(owner, &kind), owner);
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
            ptr::addr_of_mut!(KINDED_NODE_POOL_ACQUIRE).write(original);
        }
    }
}

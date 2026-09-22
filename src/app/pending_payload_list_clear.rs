//! `pending_payload_list_clear` — retailOS `FUN_08206ff4` @ `0x08206ff4`.
//!
//! Raw ARM establishes the 72-byte extent `0x08206ff4..0x0820703b`; the next
//! distinct function begins at `0x0820703c`. Whole-image A32 decoding finds
//! three plain inbound `bl` calls (`0x08206edc`, `0x08206fa8`, `0x082070d8`)
//! and no predicated inbound `bl` forms. The body has no plain `bl` instructions
//! and one predicated indirect `blxne`. It walks the owner word at `+0x20`;
//! each node supplies a payload vtable and a successor at `+0x40`. For a
//! non-null payload it dispatches vtable slot `+0x4`, passing the node itself,
//! then clears owner words `+0x20` and `+0x24` after the chain is exhausted.
//!
//! # Deliberate deviations
//!
//! The slot target is dynamic, so no callee identity or direct-call seam is
//! invented. Host fixtures use native-width pointers and semantic layouts;
//! target builds retain the firmware's 32-bit word layout and volatile reads.

const OWNER_PENDING_HEAD_WORD: usize = 0x20 / 4;
const OWNER_PENDING_TAIL_WORD: usize = 0x24 / 4;
const NODE_PAYLOAD_WORD: usize = 0;
const NODE_NEXT_WORD: usize = 0x40 / 4;
const PAYLOAD_VTABLE_SLOT: usize = 0x4 / 4;

type PayloadReleaseMethod = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_payload_release(node: *mut u8) {
    let payload_vtable = node.cast::<u32>().add(NODE_PAYLOAD_WORD).read_volatile() as usize as *const u32;
    let method: PayloadReleaseMethod = core::mem::transmute(payload_vtable.add(PAYLOAD_VTABLE_SLOT).read_volatile() as usize);
    method(node);
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostPendingPayloadVtable {
    pub unresolved_00: usize,
    pub release: PayloadReleaseMethod,
}


#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostPendingPayloadNode {
    pub payload_vtable: *const HostPendingPayloadVtable,
    pub unresolved_08_to_3f: [usize; 7],
    pub next: *mut HostPendingPayloadNode,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostPendingPayloadList {
    pub unresolved_00_to_1f: [usize; 4],
    pub head: *mut HostPendingPayloadNode,
    pub tail: *mut HostPendingPayloadNode,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_payload_release(node: *mut u8) {
    let node = &*node.cast::<HostPendingPayloadNode>();
    ((*node.payload_vtable).release)(node as *const _ as *mut u8);
}

/// Releases every pending payload in `owner`'s intrusive list.
///
/// # Safety
///
/// On target, `owner` must expose writable aligned words through `+0x24`; every
/// non-null node must expose an aligned payload word and successor at `+0x40`.
/// Each non-null payload must have a valid vtable slot `+0x4` accepting its node.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pending_payload_list_clear(owner: *mut u8) {
    #[cfg(target_os = "none")]
    let mut node = owner.cast::<u32>().add(OWNER_PENDING_HEAD_WORD).read_volatile() as usize as *mut u8;
    #[cfg(not(target_os = "none"))]
    let mut node: *mut u8 = (*owner.cast::<HostPendingPayloadList>()).head.cast();

    if node.is_null() {
        return;
    }

    loop {
        #[cfg(target_os = "none")]
        let payload = node.cast::<u32>().add(NODE_PAYLOAD_WORD).read_volatile() != 0;
        #[cfg(not(target_os = "none"))]
        let payload = !(*node.cast::<HostPendingPayloadNode>()).payload_vtable.is_null();
        #[cfg(target_os = "none")]
        let next = node.cast::<u32>().add(NODE_NEXT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(not(target_os = "none"))]
        let next: *mut u8 = (*node.cast::<HostPendingPayloadNode>()).next.cast();

        if payload {
            dispatch_payload_release(node);
        }
        if next.is_null() {
            break;
        }
        #[cfg(target_os = "none")]
        owner.cast::<u32>().add(OWNER_PENDING_HEAD_WORD).write_volatile(next as u32);
        #[cfg(not(target_os = "none"))]
        { (*owner.cast::<HostPendingPayloadList>()).head = next.cast(); }
        node = next;
    }

    #[cfg(target_os = "none")]
    {
        owner.cast::<u32>().add(OWNER_PENDING_HEAD_WORD).write_volatile(0);
        owner.cast::<u32>().add(OWNER_PENDING_TAIL_WORD).write_volatile(0);
    }
    #[cfg(not(target_os = "none"))]
    {
        let owner = &mut *owner.cast::<HostPendingPayloadList>();
        owner.head = core::ptr::null_mut();
        owner.tail = core::ptr::null_mut();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASED: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut RELEASE_COUNT: usize = 0;

    unsafe extern "C" fn record_release(node: *mut u8) {
        RELEASED[RELEASE_COUNT] = node;
        RELEASE_COUNT += 1;
    }

    #[test]
    fn releases_each_non_null_payload_in_chain_order_then_clears_owner() {
        let _lock = TEST_LOCK.lock();
        let vtable = HostPendingPayloadVtable { unresolved_00: 0, release: record_release };
        let mut second = HostPendingPayloadNode { payload_vtable: &vtable, unresolved_08_to_3f: [0; 7], next: ptr::null_mut() };
        let mut first = HostPendingPayloadNode { payload_vtable: ptr::null(), unresolved_08_to_3f: [0; 7], next: ptr::addr_of_mut!(second) };
        let mut owner = HostPendingPayloadList { unresolved_00_to_1f: [0; 4], head: ptr::addr_of_mut!(first), tail: ptr::addr_of_mut!(second) };
        unsafe {
            RELEASE_COUNT = 0;
            pending_payload_list_clear(ptr::addr_of_mut!(owner).cast());
            assert_eq!(RELEASE_COUNT, 1);
            assert_eq!(RELEASED[0], ptr::addr_of_mut!(second).cast());
        }
        assert!(owner.head.is_null());
        assert!(owner.tail.is_null());
    }

    #[test]
    fn empty_list_returns_without_changing_tail() {
        let _lock = TEST_LOCK.lock();
        let mut sentinel = HostPendingPayloadNode { payload_vtable: ptr::null(), unresolved_08_to_3f: [0; 7], next: ptr::null_mut() };
        let mut owner = HostPendingPayloadList { unresolved_00_to_1f: [0; 4], head: ptr::null_mut(), tail: ptr::addr_of_mut!(sentinel) };
        unsafe { pending_payload_list_clear(ptr::addr_of_mut!(owner).cast()); }
        assert!(owner.head.is_null());
        assert_eq!(owner.tail, ptr::addr_of_mut!(sentinel));
    }
}


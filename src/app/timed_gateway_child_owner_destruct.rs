//! Optional-child owner teardown followed by a timed gateway request.
//!
//! `timed_gateway_child_owner_destruct` — `FUN_0818beb8` @ 0x0818beb8.
//! True extent: 72 bytes (68 code + 4-byte vtable literal), ending at the
//! next real function at 0x0818bf00. Raw ARM scan finds two unconditional
//! incoming BLs (0x0818beac, 0x081a8178), zero predicated BLs; the body has
//! one direct BL and one indirect BLX. The wrapper at 0x081a8184 tail-branches
//! here. Both BL callers are NULL-guarded deleting-destructor wrappers.
//!
//! Install vtable 0x08989a10, invoke virtual slot +4 of the optional child
//! at +8, then clear that field after the callback. Always post gateway
//! payload 47 with timeout 1000 through the existing port at 0x08047f40,
//! and return the original owner. Neither the class identity nor the
//! service meaning of payload 47 is established.
//!
//! Deliberate deviations: repr(C) pointer fields and virtual slots widen on
//! hosts. Hosts explicitly install the gateway operation; target builds use
//! the existing Rust gateway port, not a new fixed-address seam.
//! Codegen review: LLVM inlines the existing timed gateway helper, yielding
//! 45 instructions versus the original's 17. The vtable store, child +8,
//! virtual slot +4, conditional clear, and owner return remain intact; the
//! inlined request uses payload 47 and timeout+1 = 1001.

#[repr(C)]
pub struct TimedGatewayChildOwner {
    pub vtable: usize,
    pub state: u32,
    pub child: *mut GatewayOwnedChild,
    pub selection: u8,
    pub flag: u8,
    pub reserved: [u8; 2],
}

#[repr(C)]
pub struct GatewayOwnedChild {
    pub vtable: *const GatewayOwnedChildVtable,
}

#[repr(C)]
pub struct GatewayOwnedChildVtable {
    pub first_slot: usize,
    pub destruct: unsafe extern "C" fn(*mut GatewayOwnedChild),
}

pub const TIMED_GATEWAY_OWNER_VTABLE: usize = 0x0898_9a10;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_gateway(_: usize, _: usize) {
    panic!("install timed gateway owner host gateway operation")
}

#[cfg(not(target_os = "none"))]
pub static mut TIMED_GATEWAY_OWNER_REQUEST: unsafe extern "C" fn(usize, usize) = missing_gateway;

/// # Safety
/// `owner` must be writable and non-null. A non-null child must have a valid
/// vtable and second virtual slot. Hosts must install the gateway operation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timed_gateway_child_owner_destruct(
    owner: *mut TimedGatewayChildOwner,
) -> *mut TimedGatewayChildOwner {
    (*owner).vtable = TIMED_GATEWAY_OWNER_VTABLE;
    let child = (*owner).child;
    if !child.is_null() {
        ((*(*child).vtable).destruct)(child);
        (*owner).child = core::ptr::null_mut();
    }
    #[cfg(target_os = "none")]
    crate::kernel::gateway_request::gateway_request_timed(47, 1000);
    #[cfg(not(target_os = "none"))]
    (core::ptr::read_volatile(core::ptr::addr_of!(TIMED_GATEWAY_OWNER_REQUEST)))(47, 1000);
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut OWNER: *mut TimedGatewayChildOwner = ptr::null_mut();
    static mut CHILD_CALLS: usize = 0;
    static mut REQUESTS: usize = 0;
    static mut REPLACEMENT: GatewayOwnedChild = GatewayOwnedChild { vtable: ptr::null() };

    unsafe extern "C" fn destroy_child(child: *mut GatewayOwnedChild) {
        assert_eq!((*OWNER).vtable, TIMED_GATEWAY_OWNER_VTABLE);
        assert_eq!((*OWNER).child, child, "clear only after virtual destruction");
        CHILD_CALLS += 1;
        // A callback may replace the field; stock code still clears it.
        (*OWNER).child = ptr::addr_of_mut!(REPLACEMENT);
        (*OWNER).state = 0x1234_abcd;
    }

    unsafe extern "C" fn request(_: usize, _: usize) {
        assert!((*OWNER).child.is_null(), "gateway must observe completed teardown");
        assert_eq!((*OWNER).vtable, TIMED_GATEWAY_OWNER_VTABLE);
        REQUESTS += 1;
    }

    #[test]
    fn optional_child_teardown_and_repeated_destroy() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = TIMED_GATEWAY_OWNER_REQUEST;
            TIMED_GATEWAY_OWNER_REQUEST = request;
            CHILD_CALLS = 0;
            REQUESTS = 0;
            let table = GatewayOwnedChildVtable { first_slot: 0, destruct: destroy_child };
            let mut child = GatewayOwnedChild { vtable: &table };
            let mut owner = TimedGatewayChildOwner { vtable: 0, state: 7, child: &mut child, selection: 3, flag: 4, reserved: [5, 6] };
            OWNER = &mut owner;
            assert_eq!(timed_gateway_child_owner_destruct(&mut owner), &mut owner as *mut _);
            assert!(owner.child.is_null());
            assert_eq!(owner.state, 0x1234_abcd, "preserve callback mutations");
            assert_eq!(timed_gateway_child_owner_destruct(&mut owner), &mut owner as *mut _);
            assert_eq!(ptr::addr_of!(CHILD_CALLS).read(), 1, "never destroy the child twice");
            assert_eq!(ptr::addr_of!(REQUESTS).read(), 2, "NULL path still posts a request");
            TIMED_GATEWAY_OWNER_REQUEST = saved;
            OWNER = ptr::null_mut();
        }
    }

    #[test]
    fn initially_null_child_preserves_unrelated_state() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = TIMED_GATEWAY_OWNER_REQUEST;
            TIMED_GATEWAY_OWNER_REQUEST = request;
            CHILD_CALLS = 0;
            REQUESTS = 0;
            let mut owner = TimedGatewayChildOwner { vtable: usize::MAX, state: u32::MAX, child: ptr::null_mut(), selection: 3, flag: 4, reserved: [5, 6] };
            OWNER = &mut owner;
            assert_eq!(timed_gateway_child_owner_destruct(&mut owner), &mut owner as *mut _);
            assert_eq!(owner.state, u32::MAX);
            assert_eq!(ptr::addr_of!(CHILD_CALLS).read(), 0);
            assert_eq!(ptr::addr_of!(REQUESTS).read(), 1);
            TIMED_GATEWAY_OWNER_REQUEST = saved;
            OWNER = ptr::null_mut();
        }
    }
}

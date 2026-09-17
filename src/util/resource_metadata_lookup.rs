//! Resource-metadata lookup wrapper ported from retailOS `0x082e46c0`.
//!
//! Load address: `0x082e46c0`; true size: 112 bytes (`0x70`), ending in
//! `ldmia sp!, {r4-r8, pc}` before the next function at `0x082e4730`.
//! Decoding the raw ARM words verifies seven unconditional `bl` instructions
//! in the body and four inbound direct calls, all unconditional `bl`.
//!
//! The wrapper acquires a numbered guard, looks up `resource`, copies metadata
//! from the found node's word at `+0x04` into `out`, releases the node and
//! guard, then publishes status zero on success or two on a lookup miss.
//! A negative guard acquisition returns `-1` without publishing status.
//! Deliberate deviation: the seven unresolved retailOS callees are represented
//! by target-address calls and a replaceable host seam; their semantic
//! identities remain unproven.

#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of, read_volatile};

pub type AcquireGuard = unsafe extern "C" fn() -> i32;
pub type GuardOperation = unsafe extern "C" fn(i32);
pub type ResourceLookup = unsafe extern "C" fn(*mut u8) -> *mut u32;
pub type MetadataCopy = unsafe extern "C" fn(u32, *mut u8);
pub type NodeRelease = unsafe extern "C" fn(*mut u32);
pub type StatusPublish = unsafe extern "C" fn(u32);

#[derive(Clone, Copy)]
pub struct ResourceMetadataLookupOps {
    pub acquire_guard: AcquireGuard,
    pub lock_guard: GuardOperation,
    pub lookup_resource: ResourceLookup,
    pub copy_metadata: MetadataCopy,
    pub release_node: NodeRelease,
    pub unlock_guard: GuardOperation,
    pub publish_status: StatusPublish,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn acquire_guard() -> i32 { (core::mem::transmute::<usize, AcquireGuard>(0x082c_3000))() }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lock_guard(guard: i32) { (core::mem::transmute::<usize, GuardOperation>(0x082d_7934))(guard) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_resource(resource: *mut u8) -> *mut u32 { (core::mem::transmute::<usize, ResourceLookup>(0x082e_15d8))(resource) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn copy_metadata(node_data: u32, out: *mut u8) { (core::mem::transmute::<usize, MetadataCopy>(0x082e_1390))(node_data, out) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_node(node: *mut u32) { (core::mem::transmute::<usize, NodeRelease>(0x082e_19cc))(node) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlock_guard(guard: i32) { (core::mem::transmute::<usize, GuardOperation>(0x082d_7954))(guard) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn publish_status(status: u32) { (core::mem::transmute::<usize, StatusPublish>(0x0836_90a8))(status) }

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_acquire_guard() -> i32 { -1 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_guard_operation(_: i32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup_resource(_: *mut u8) -> *mut u32 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_copy_metadata(_: u32, _: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_node(_: *mut u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_publish_status(_: u32) {}

#[cfg(not(target_os = "none"))]
const DEFAULT_OPS: ResourceMetadataLookupOps = ResourceMetadataLookupOps {
    acquire_guard: missing_acquire_guard,
    lock_guard: missing_guard_operation,
    lookup_resource: missing_lookup_resource,
    copy_metadata: missing_copy_metadata,
    release_node: missing_release_node,
    unlock_guard: missing_guard_operation,
    publish_status: missing_publish_status,
};

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: ResourceMetadataLookupOps = DEFAULT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ops() -> ResourceMetadataLookupOps { read_volatile(addr_of!(HOST_OPS)) }

/// Looks up `resource` and writes its retailOS metadata record to `out`.
///
/// `resource` and `out` must meet the unresolved retail lookup and metadata
/// copier contracts. Stock code performs no NULL checks on either argument.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_metadata_lookup(resource: *mut u8, out: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    let guard = acquire_guard();
    #[cfg(not(target_os = "none"))]
    let guard = (ops().acquire_guard)();
    if guard < 0 { return -1; }
    #[cfg(target_os = "none")]
    lock_guard(guard);
    #[cfg(not(target_os = "none"))]
    (ops().lock_guard)(guard);
    #[cfg(target_os = "none")]
    let node = lookup_resource(resource);
    #[cfg(not(target_os = "none"))]
    let node = (ops().lookup_resource)(resource);
    let mut status = 2;
    let result = if node.is_null() {
        -1
    } else {
        #[cfg(target_os = "none")]
        copy_metadata(node.add(1).read(), out);
        #[cfg(not(target_os = "none"))]
        (ops().copy_metadata)(node.add(1).read(), out);
        status = 0;
        #[cfg(target_os = "none")]
        release_node(node);
        #[cfg(not(target_os = "none"))]
        (ops().release_node)(node);
        0
    };
    #[cfg(target_os = "none")]
    unlock_guard(guard);
    #[cfg(not(target_os = "none"))]
    (ops().unlock_guard)(guard);
    #[cfg(target_os = "none")]
    publish_status(status);
    #[cfg(not(target_os = "none"))]
    (ops().publish_status)(status);
    result
}
#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;
    use core::ptr::{addr_of_mut, write_volatile};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u32; 8] = [0; 8];
    static mut EVENT_COUNT: usize = 0;
    static mut ACQUIRE_RESULT: i32 = -1;
    static mut LOOKUP_RESULT: *mut u32 = core::ptr::null_mut();

    unsafe fn event(value: u32) { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; }
    unsafe extern "C" fn acquire() -> i32 { event(1); ACQUIRE_RESULT }
    unsafe extern "C" fn lock(guard: i32) { event(0x10 + guard as u32); }
    unsafe extern "C" fn lookup(_: *mut u8) -> *mut u32 { event(3); LOOKUP_RESULT }
    unsafe extern "C" fn copy(source: u32, _: *mut u8) { event(0x40 + source); }
    unsafe extern "C" fn release(_: *mut u32) { event(5); }
    unsafe extern "C" fn unlock(guard: i32) { event(0x60 + guard as u32); }
    unsafe extern "C" fn publish(status: u32) { event(0x80 + status); }

    unsafe fn install(acquire_result: i32, lookup_result: *mut u32) -> ResourceMetadataLookupOps {
        ACQUIRE_RESULT = acquire_result;
        LOOKUP_RESULT = lookup_result;
        EVENT_COUNT = 0;
        let previous = read_volatile(addr_of!(HOST_OPS));
        write_volatile(addr_of_mut!(HOST_OPS), ResourceMetadataLookupOps {
            acquire_guard: acquire, lock_guard: lock, lookup_resource: lookup,
            copy_metadata: copy, release_node: release, unlock_guard: unlock, publish_status: publish,
        });
        previous
    }

    #[test]
    fn preserves_guard_failure_and_lookup_lifecycle() {
        let _lock = OPS_LOCK.lock();
        unsafe {
            let previous = install(-1, core::ptr::null_mut());
            assert_eq!(resource_metadata_lookup(core::ptr::null_mut(), core::ptr::null_mut()), -1);

            let mut node = [0, 7];
            install(4, node.as_mut_ptr());
            assert_eq!(resource_metadata_lookup(core::ptr::null_mut(), core::ptr::null_mut()), 0);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 0x14, 3, 0x47, 5, 0x64, 0x80]);

            install(4, core::ptr::null_mut());
            assert_eq!(resource_metadata_lookup(core::ptr::null_mut(), core::ptr::null_mut()), -1);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[1, 0x14, 3, 0x64, 0x82]);
            write_volatile(addr_of_mut!(HOST_OPS), previous);
        }
    }
}

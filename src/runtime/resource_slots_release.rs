//! Resource-slot release port.
//!
//! The four target-width resource words are deliberately accessed by word index:
//! host pointers are wider than the retailOS pointers at offsets `+0x28..+0x34`.

use core::ptr;

/// Operations reached by `resource_slots_release` that remain outside the port.
///
/// Target defaults preserve each verified retail call target. Host tests replace
/// them to observe order and arguments without calling firmware addresses.
#[derive(Clone, Copy)]
pub struct ResourceSlotReleaseOps {
    pub release_tracked_resource: unsafe extern "C" fn(u32),
    pub free_tagged_resource: unsafe extern "C" fn(u32, u32),
    pub destroy_and_delete_resource: unsafe extern "C" fn(u32),
    pub release_pool_resource: unsafe extern "C" fn(u32),
    pub set_memory_soft_limit: unsafe extern "C" fn(i32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn release_tracked_resource(resource: u32) {
    let release: unsafe extern "C" fn(u32) = unsafe { core::mem::transmute(0x082c_a974usize) };
    unsafe { release(resource) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release_tracked_resource(_resource: u32) {
    panic!("resource_slots_release requires release target 0x082ca974")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn free_tagged_resource(resource: u32, tag: u32) {
    let free: unsafe extern "C" fn(u32, u32) = unsafe { core::mem::transmute(0x080e_7970usize) };
    unsafe { free(resource, tag) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_free_tagged_resource(_resource: u32, _tag: u32) {
    panic!("resource_slots_release requires free target 0x080e7970")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn destroy_and_delete_resource(resource: u32) {
    let destroy: unsafe extern "C" fn(u32) = unsafe { core::mem::transmute(0x0815_9c08usize) };
    unsafe { destroy(resource) };
    let delete: unsafe extern "C" fn(u32) = unsafe { core::mem::transmute(0x082a_ad24usize) };
    unsafe { delete(resource) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_destroy_and_delete_resource(_resource: u32) {
    panic!("resource_slots_release requires destroy target 0x08159c08")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn release_pool_resource(resource: u32) {
    let release: unsafe extern "C" fn(u32) = unsafe { core::mem::transmute(0x082c_acd4usize) };
    unsafe { release(resource) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release_pool_resource(_resource: u32) {
    panic!("resource_slots_release requires release target 0x082cacd4")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn set_memory_soft_limit(limit: i32) {
    let set_limit: unsafe extern "C" fn(i32) = unsafe { core::mem::transmute(0x0813_eb3cusize) };
    unsafe { set_limit(limit) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_set_memory_soft_limit(_limit: i32) {
    panic!("resource_slots_release requires soft-limit target 0x0813eb3c")
}

#[cfg(target_os = "none")]
const DEFAULT_RESOURCE_SLOT_RELEASE_OPS: ResourceSlotReleaseOps = ResourceSlotReleaseOps {
    release_tracked_resource,
    free_tagged_resource,
    destroy_and_delete_resource,
    release_pool_resource,
    set_memory_soft_limit,
};
#[cfg(not(target_os = "none"))]
const DEFAULT_RESOURCE_SLOT_RELEASE_OPS: ResourceSlotReleaseOps = ResourceSlotReleaseOps {
    release_tracked_resource: unavailable_release_tracked_resource,
    free_tagged_resource: unavailable_free_tagged_resource,
    destroy_and_delete_resource: unavailable_destroy_and_delete_resource,
    release_pool_resource: unavailable_release_pool_resource,
    set_memory_soft_limit: unavailable_set_memory_soft_limit,
};

static mut RESOURCE_SLOT_RELEASE_OPS: ResourceSlotReleaseOps = DEFAULT_RESOURCE_SLOT_RELEASE_OPS;

/// `resource_slots_release` — original: `FUN_0816eb70` @ `0x0816eb70`.
///
/// True size: 112 bytes (`0x0816eb70..0x0816ebdf`), ending in the tail branch
/// to the soft-limit thunk at `0x0813eb3c`; 5 plain `bl` calls and no
/// predicated `bl` calls, decoded from `osos.dec`. Releases each nonzero
/// target-word resource at `this+0x28`, `+0x2c`, `+0x30`, and `+0x34`, clears
/// the corresponding word after its release, then tail-calls the memory-soft-
/// limit path with 524288 bytes. The `+0x30` release is its destructor
/// (`0x08159c08`) followed by `operator_delete` (`0x082aad24`).
///
/// Deliberate deviation: opaque release targets and the soft-limit thunk use
/// replaceable operation slots so host tests do not call firmware addresses;
/// target defaults call their verified addresses. The field words stay `u32`
/// rather than host pointers to preserve the retail 4-byte layout.
///
/// # Safety
///
/// `this` must be non-NULL, 4-byte aligned, and point to at least 56 writable
/// bytes in the retail target-word layout.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_slots_release(this: *mut u32) {
    let ops = unsafe { ptr::read_volatile(ptr::addr_of!(RESOURCE_SLOT_RELEASE_OPS)) };
    let resource = unsafe { this.add(10).read() };
    if resource != 0 {
        unsafe { (ops.release_tracked_resource)(resource) };
        unsafe { this.add(10).write(0) };
    }
    let resource = unsafe { this.add(11).read() };
    if resource != 0 {
        unsafe { (ops.free_tagged_resource)(resource, 0) };
        unsafe { this.add(11).write(0) };
    }
    let resource = unsafe { this.add(12).read() };
    if resource != 0 {
        unsafe { (ops.destroy_and_delete_resource)(resource) };
        unsafe { this.add(12).write(0) };
    }
    let resource = unsafe { this.add(13).read() };
    if resource != 0 {
        unsafe { (ops.release_pool_resource)(resource) };
        unsafe { this.add(13).write(0) };
    }
    unsafe { (ops.set_memory_soft_limit)(0x80000) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u32; 8] = [0; 8];
    static mut EVENT_COUNT: usize = 0;

    unsafe fn record(event: u32) {
        unsafe { EVENTS[EVENT_COUNT] = event; EVENT_COUNT += 1 }
    }
    unsafe extern "C" fn tracked(resource: u32) { unsafe { record(0x1000_0000 | resource) } }
    unsafe extern "C" fn tagged(resource: u32, tag: u32) { unsafe { record(0x2000_0000 | resource | tag) } }
    unsafe extern "C" fn destroy(resource: u32) { unsafe { record(0x3000_0000 | resource) } }
    unsafe extern "C" fn pool(resource: u32) { unsafe { record(0x4000_0000 | resource) } }
    unsafe extern "C" fn soft_limit(limit: i32) { unsafe { record(limit as u32) } }

    struct Seams { _lock: MutexGuard<'static, ()>, saved: ResourceSlotReleaseOps }
    impl Drop for Seams {
        fn drop(&mut self) { unsafe { RESOURCE_SLOT_RELEASE_OPS = self.saved } }
    }
    fn install() -> Seams {
        let lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let saved = RESOURCE_SLOT_RELEASE_OPS;
            RESOURCE_SLOT_RELEASE_OPS = ResourceSlotReleaseOps {
                release_tracked_resource: tracked, free_tagged_resource: tagged,
                destroy_and_delete_resource: destroy, release_pool_resource: pool,
                set_memory_soft_limit: soft_limit,
            };
            EVENTS = [0; 8]; EVENT_COUNT = 0;
            Seams { _lock: lock, saved }
        }
    }

    #[test]
    fn releases_nonzero_slots_in_order_then_sets_the_soft_limit() {
        let _seams = install();
        let mut object = [0xfeed_face; 14];
        object[10..14].copy_from_slice(&[1, 2, 3, 4]);
        unsafe { resource_slots_release(object.as_mut_ptr()) };
        assert_eq!(&object[10..14], &[0; 4]);
        assert_eq!(unsafe { &EVENTS[..EVENT_COUNT] }, &[0x1000_0001, 0x2000_0002, 0x3000_0003, 0x4000_0004, 0x80000]);
    }

    #[test]
    fn skips_empty_slots_but_always_sets_the_soft_limit() {
        let _seams = install();
        let mut object = [0; 14];
        object[..10].fill(0xfeed_face);
        unsafe { resource_slots_release(object.as_mut_ptr()) };
        assert_eq!(unsafe { &EVENTS[..EVENT_COUNT] }, &[0x80000]);
        assert_eq!(&object[10..14], &[0; 4]);
    }
}

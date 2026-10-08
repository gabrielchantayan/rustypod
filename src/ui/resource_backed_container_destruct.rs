//! Resource-backed container destructor, FUN_0811e4f8 @ 0x0811e4f8.
//!
//! True extent 60 bytes: 56 code bytes and the vtable literal at
//! 0x0811e530; the next real function starts at 0x0811e534. Whole-image
//! raw A32 decoding finds two inbound plain BLs, zero predicated BLs,
//! and no data-word references. Body: one plain BL, zero predicated BLs,
//! one BLX through slot +0x114, and a tail B to 0x0815880c.
//!
//! Install vtable 0x08982d34, dispatch its +0x114 teardown slot, reload
//! resource +0xe8, call 0x08148e0c even for zero, clear the resource,
//! and return the existing container destructor's result. The release
//! helper performs global cleanup before optionally freeing its argument;
//! it is not a plain free. The concrete widget identity is unresolved.
//!
//! Deviations: host-only callbacks replace the runtime ROM slot, unported
//! resource release, and base destruction. The latter avoids interpreting
//! the target's 0x28-byte registry as the larger host-pointer Registry.
//! Target builds dispatch the real slot and release helper, and call the
//! existing Rust container destructor directly. No null guard is added.
use super::container_view::ContainerView;
#[cfg(target_os = "none")]
use super::container_view::container_view_destruct;

pub const RESOURCE_CONTAINER_VTABLE: u32 = 0x0898_2d34;
const RESOURCE_WORD: usize = 0xe8 / 4;
type Teardown = unsafe extern "C" fn(*mut u32);
type Release = unsafe extern "C" fn(u32);
type DestructBase = unsafe extern "C" fn(*mut ContainerView) -> *mut ContainerView;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct HostResourceContainerOps {
    pub teardown_slot_114: Teardown,
    pub release_resource: Release,
    pub destruct_base: DestructBase,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_teardown(_: *mut u32) {
    panic!("resource container requires runtime vtable slot +0x114")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_: u32) {
    panic!("resource container requires release helper 0x08148e0c")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base(_: *mut ContainerView) -> *mut ContainerView {
    panic!("resource container requires a host-layout base destructor")
}

#[cfg(not(target_os = "none"))]
pub static mut HOST_RESOURCE_CONTAINER_OPS: HostResourceContainerOps = HostResourceContainerOps {
    teardown_slot_114: missing_teardown,
    release_resource: missing_release,
    destruct_base: missing_base,
};

/// Tear down the derived resource before destroying the container base.
///
/// # Safety
/// `view` must be aligned and writable through +0xe8, with a valid base
/// container and resource. Runtime slot +0x114 must accept it. On hosts,
/// install callbacks satisfying the same teardown/release contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_backed_container_destruct(view: *mut u32) -> *mut u32 {
    view.write_volatile(RESOURCE_CONTAINER_VTABLE);
    #[cfg(target_os = "none")]
    let teardown: Teardown = core::mem::transmute(
        (RESOURCE_CONTAINER_VTABLE as usize as *const u32).add(0x114 / 4).read_volatile() as usize,
    );
    #[cfg(not(target_os = "none"))]
    let teardown = core::ptr::addr_of!(HOST_RESOURCE_CONTAINER_OPS.teardown_slot_114).read();
    teardown(view);
    let resource = view.add(RESOURCE_WORD).read_volatile();
    #[cfg(target_os = "none")]
    let release: Release = core::mem::transmute(0x0814_8e0cusize);
    #[cfg(not(target_os = "none"))]
    let release = core::ptr::addr_of!(HOST_RESOURCE_CONTAINER_OPS.release_resource).read();
    release(resource);
    view.add(RESOURCE_WORD).write_volatile(0);
    #[cfg(target_os = "none")]
    let base: DestructBase = container_view_destruct;
    #[cfg(not(target_os = "none"))]
    let base = core::ptr::addr_of!(HOST_RESOURCE_CONTAINER_OPS.destruct_base).read();
    base(view.cast()).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut REPLACEMENT: u32 = 0;
    static mut OWNER: *mut u32 = core::ptr::null_mut();
    static mut PHASE: u32 = 0;

    unsafe extern "C" fn teardown(view: *mut u32) {
        assert_eq!(PHASE, 0);
        assert_eq!(view, OWNER);
        assert_eq!(view.read(), RESOURCE_CONTAINER_VTABLE);
        view.add(RESOURCE_WORD).write(REPLACEMENT);
        PHASE = 1;
    }
    unsafe extern "C" fn release(resource: u32) {
        assert_eq!(PHASE, 1);
        assert_eq!(resource, REPLACEMENT);
        assert_eq!(OWNER.add(RESOURCE_WORD).read(), resource);
        // Even a release callback that rewrites the resource must be
        // followed by the caller's clear, not left with a stale handle.
        OWNER.add(RESOURCE_WORD).write(0xdead_beef);
        PHASE = 2;
    }
    unsafe extern "C" fn base(view: *mut ContainerView) -> *mut ContainerView {
        assert_eq!(PHASE, 2);
        assert_eq!(view.cast::<u32>(), OWNER);
        assert_eq!(OWNER.add(RESOURCE_WORD).read(), 0);
        PHASE = 3;
        // Check result forwarding, rather than assuming base returns this.
        OWNER.add(1).cast()
    }

    #[test]
    fn reloads_after_virtual_teardown_clears_after_release_and_forwards_base_result() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = HOST_RESOURCE_CONTAINER_OPS;
            HOST_RESOURCE_CONTAINER_OPS = HostResourceContainerOps {
                teardown_slot_114: teardown, release_resource: release, destruct_base: base,
            };
            for (before, after) in [(0, 0), (0x1234, 0), (0, 0x8123_4560),
                                    (0x1234, 0xffff_fffc)] {
                let mut view = [0xa5a5_1234u32; 0xec / 4];
                view[RESOURCE_WORD] = before;
                OWNER = view.as_mut_ptr();
                REPLACEMENT = after;
                PHASE = 0;
                assert_eq!(resource_backed_container_destruct(OWNER), OWNER.add(1));
                assert_eq!(PHASE, 3);
                assert_eq!(view[RESOURCE_WORD], 0);
                for word in &view[1..RESOURCE_WORD] { assert_eq!(*word, 0xa5a5_1234); }
            }
            HOST_RESOURCE_CONTAINER_OPS = saved;
        }
    }
}

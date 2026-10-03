//! Keyed child refresh — `FUN_082339f0` at **0x082339f0**.
//!
//! True extent: **112 bytes**, 104 instruction bytes plus two key literals;
//! the next function starts at 0x08233a60. Raw-word scan: two inbound plain
//! BL calls (0x082339a0, 0x08233ac4), zero predicated BL calls. The body has
//! five plain BL instructions, zero predicated BL, one BLX, and a conditional
//! tail B to 0x0812eaf4. Query slot +0xc4; choose key 0x0dad0343 for zero,
//! otherwise 0x0dad0345. Resolve through TCDemoMode, cast to class 0x1580,
//! read its +0x34 child, cast that to 0x3b80, and refresh its current value.
//! The verified tail helper reads +0x58, sign-extends its low halfword, and
//! dispatches slot +0x164. Both callers refresh after stepping a value +/-1.
//!
//! Deliberate deviations: native-pointer repr(C) models expand on hosts but
//! retain target word indices. Host-only operations replace firmware calls;
//! target uses existing Rust registry ports and the verified unported helper
//! directly. The conditional tail branch is expressed as a final void call.
//! No null guard is added before the first cast result's +0x34 dereference.

#[repr(C)]
pub struct RefreshOwnerVtable {
    pub unresolved: [usize; 0xc4 / 4],
    pub selection: unsafe extern "C" fn(*mut RefreshOwner) -> u32,
}

#[repr(C)]
pub struct RefreshOwner {
    pub vtable: *const RefreshOwnerVtable,
}

#[repr(C)]
struct ChildContainer {
    vtable: usize,
    unresolved: [usize; 12],
    child: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x34] = [(); core::mem::offset_of!(ChildContainer, child)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0xc4] = [(); core::mem::offset_of!(RefreshOwnerVtable, selection)];

#[cfg(target_os = "none")]
unsafe fn resolve(key: u32) -> *mut u8 {
    use crate::app::registry::{demo_mode_instance, demo_mode_keyed_object};
    demo_mode_keyed_object(demo_mode_instance().cast(), key)
}
#[cfg(target_os = "none")]
unsafe fn cast(object: *mut u8, class: u32) -> *mut u8 {
    crate::app::registry::object_cast_to_class(object.cast(), class)
}
#[cfg(target_os = "none")]
unsafe fn refresh(object: *mut u8) {
    let dispatch: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0812eaf4usize);
    dispatch(object);
}

#[cfg(not(target_os = "none"))]
struct HostOps {
    resolve: unsafe fn(u32) -> *mut u8,
    cast: unsafe fn(*mut u8, u32) -> *mut u8,
    refresh: unsafe fn(*mut u8),
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps {
    resolve: |_| panic!("install keyed resolver"),
    cast: |_, _| panic!("install class cast"),
    refresh: |_| panic!("install current-value dispatch"),
};
#[cfg(not(target_os = "none"))]
unsafe fn resolve(key: u32) -> *mut u8 { (HOST_OPS.resolve)(key) }
#[cfg(not(target_os = "none"))]
unsafe fn cast(object: *mut u8, class: u32) -> *mut u8 { (HOST_OPS.cast)(object, class) }
#[cfg(not(target_os = "none"))]
unsafe fn refresh(object: *mut u8) { (HOST_OPS.refresh)(object) }

/// Refreshes the selected keyed object's child with its existing value.
///
/// # Safety
/// Owner, its virtual method, and the resolved class-0x1580 container must be
/// valid. The non-null child's cast and current-value dispatch must be valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn keyed_child_refresh(owner: *mut RefreshOwner) {
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*owner).vtable));
    let selection = ((*vtable).selection)(owner);
    let key = if selection == 0 { 0x0dad0343 } else { 0x0dad0345 };
    let container = cast(resolve(key), 0x1580).cast::<ChildContainer>();
    let child = core::ptr::read_volatile(core::ptr::addr_of!((*container).child));
    if child.is_null() { return; }
    let child = cast(child, 0x3b80);
    if !child.is_null() && !container.is_null() { refresh(child); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut SELECTION: u32 = 0;
    static mut CONTAINERS: [*mut ChildContainer; 2] = [core::ptr::null_mut(); 2];
    static mut REJECT: bool = false;
    static mut REFRESHED: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn selection(_: *mut RefreshOwner) -> u32 { SELECTION }
    unsafe fn resolve(key: u32) -> *mut u8 {
        match key {
            0x0dad0343 => CONTAINERS[0].cast(),
            0x0dad0345 => CONTAINERS[1].cast(),
            _ => panic!("unexpected key"),
        }
    }
    unsafe fn cast(object: *mut u8, class: u32) -> *mut u8 {
        match class {
            0x1580 => object,
            0x3b80 => if REJECT { core::ptr::null_mut() } else { object },
            _ => panic!("unexpected class"),
        }
    }
    unsafe fn refresh(object: *mut u8) { REFRESHED = object; }

    #[test]
    fn selects_both_keys_and_skips_absent_or_rejected_children() {
        let _lock = LOCK.lock();
        let vtable = RefreshOwnerVtable { unresolved: [0; 49], selection };
        let mut owner = RefreshOwner { vtable: &vtable };
        let mut children = [0u32; 2];
        let mut containers = [
            ChildContainer { vtable: 0, unresolved: [0; 12], child: children.as_mut_ptr().cast() },
            ChildContainer { vtable: 0, unresolved: [0; 12], child: unsafe { children.as_mut_ptr().add(1).cast() } },
        ];
        unsafe {
            HOST_OPS = HostOps { resolve, cast, refresh };
            CONTAINERS = [containers.as_mut_ptr(), containers.as_mut_ptr().add(1)];
            for value in [0, 1, u32::MAX] {
                SELECTION = value;
                REJECT = false;
                REFRESHED = core::ptr::null_mut();
                keyed_child_refresh(&mut owner);
                assert_eq!(REFRESHED, containers[usize::from(value != 0)].child);
            }
            REJECT = true;
            REFRESHED = core::ptr::null_mut();
            keyed_child_refresh(&mut owner);
            assert!(REFRESHED.is_null());
            REJECT = false;
            containers[1].child = core::ptr::null_mut();
            keyed_child_refresh(&mut owner);
            assert!(REFRESHED.is_null());
        }
    }
}

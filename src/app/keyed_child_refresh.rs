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
//! target uses existing Rust registry ports and current-value dispatch directly.
//! The conditional tail branch is expressed as a final void call.
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
unsafe fn refresh(object: *mut u8) {
    super::current_value_virtual_dispatch::current_value_virtual_dispatch(object.cast());
}

#[cfg(not(target_os = "none"))]
struct HostOps {
    resolve: unsafe fn(u32) -> *mut u8,
    cast: unsafe fn(*mut u8, u32) -> *mut u8,
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps {
    resolve: |_| panic!("install keyed resolver"),
    cast: |_, _| panic!("install class cast"),
};
#[cfg(not(target_os = "none"))]
unsafe fn resolve(key: u32) -> *mut u8 { (HOST_OPS.resolve)(key) }
#[cfg(not(target_os = "none"))]
unsafe fn cast(object: *mut u8, class: u32) -> *mut u8 { (HOST_OPS.cast)(object, class) }

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


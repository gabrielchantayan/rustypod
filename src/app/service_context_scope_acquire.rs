//! Service-context scope acquisition — FUN_08155b24 @ 0x08155b24.
//! True extent: 40 bytes [0x08155b24, 0x08155b4c); the next word is an
//! independent push. Raw A32 decoding finds two outbound plain BLs and zero
//! predicated BLs; inbound calls at 0x0813c518 and 0x0813c77c are both BLEQ
//! (zero plain, two predicated). Allocate a one-pointer cell, store the scope
//! back-pointer, enter the service-context gate, then publish the cell in the
//! scope. No existing-cell check, release, or allocation-failure guard.
//!
//! Deviations: repr(C) pointer fields and allocation size widen together on
//! hosts; target scope is eight bytes and cell four bytes. Reuse operator_new.
//! The unported gate remains resident at 0x0820c208 on ARM and must be supplied
//! on hosts. Raw gate code ignores incoming r0; its semantic signature is void.
//! match.py reports the expected structural diff (exit 1): LLVM adds a frame
//! pointer, replaces the resident BL with literal-address BLX, and omits the
//! unused gate argument. Four-byte allocation and both ordered stores remain.
use crate::heap::veneers::operator_new;

#[repr(C)]
pub struct ServiceContextScope {
    pub vtable: *const u8,
    pub cell: *mut *mut ServiceContextScope,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_gate() {
    panic!("install resident service-context gate @ 0x0820c208")
}

#[cfg(not(target_os = "none"))]
pub static mut SERVICE_CONTEXT_SCOPE_ENTER: unsafe extern "C" fn() = unavailable_gate;

/// # Safety
/// Scope must be writable and allocation must return a non-NULL aligned cell.
/// The resident service-context globals must be initialized. Host gate changes
/// require external serialization. An old cell is overwritten without freeing.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_context_scope_acquire(scope: *mut ServiceContextScope) {
    #[cfg(target_os = "none")]
    let enter: unsafe extern "C" fn() = core::mem::transmute(0x0820_c208usize);
    #[cfg(not(target_os = "none"))]
    let enter = core::ptr::addr_of!(SERVICE_CONTEXT_SCOPE_ENTER).read();
    acquire(scope, |size| operator_new(size), || enter());
}

#[inline(always)]
unsafe fn acquire(
    scope: *mut ServiceContextScope,
    allocate: impl FnOnce(usize) -> *mut u8,
    enter: impl FnOnce(),
) {
    let cell = allocate(core::mem::size_of::<*mut ServiceContextScope>())
        .cast::<*mut ServiceContextScope>();
    cell.write(scope);
    enter();
    core::ptr::addr_of_mut!((*scope).cell).write(cell);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_observes_initialized_back_pointer_but_not_published_cell() {
        for occupied in [false, true] {
            let mut old_cell: *mut ServiceContextScope = core::ptr::null_mut();
            let old = if occupied { &mut old_cell as *mut _ } else { core::ptr::null_mut() };
            let mut scope = ServiceContextScope { vtable: 0x1234usize as *const u8, cell: old };
            let scope_ptr = &mut scope as *mut ServiceContextScope;
            let mut new_cell = core::ptr::null_mut();
            let new = &mut new_cell as *mut *mut ServiceContextScope;
            unsafe {
                acquire(scope_ptr, |size| {
                    assert_eq!(size, core::mem::size_of_val(&new_cell));
                    new.cast()
                }, || {
                    assert_eq!(new.read(), scope_ptr);
                    assert_eq!((*scope_ptr).cell, old);
                    // A gate-side update must be overwritten by final publication.
                    (*scope_ptr).cell = core::ptr::null_mut();
                });
            }
            assert_eq!(scope.cell, new);
            assert_eq!(new_cell, scope_ptr);
            assert_eq!(scope.vtable, 0x1234usize as *const u8);
            assert!(old_cell.is_null());
        }
    }
}

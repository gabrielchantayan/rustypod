//! Query-backed kind-20 controller constructor, retailOS `FUN_08239d34`
//! @ 0x08239d34. True extent: 120 bytes (116 code plus vtable literal
//! @ 0x08239da8); next real function begins @ 0x08239dac.
//! Raw A32 decoding: two inbound plain BLs, zero predicated inbound BLs;
//! six outbound plain BLs, zero predicated outbound BLs.
//!
//! Allocates and constructs a 72-byte query (id/mode zero), wraps it in a
//! temporary refcounted handle, constructs the kinded base with kind 20 and
//! all optional flags zero, releases the temporary, installs vtable
//! 0x089a2ce8, and constructs a null-subject context scope at +0xd0.
//! Returns the base constructor's object, not necessarily the input.
//! Deviations: reuses existing Rust callees and the shared query constructor
//! seam; initializes the temporary slot rather than preserving incoming r3
//! (overwritten before any read). Ignores incoming r1/r2/r3, which raw code
//! never consumes. Vtable is a target u32 address, not a host pointer.

use crate::app::context_scope::context_scope_init;
use crate::app::kinded_controller::kinded_controller_construct;
use crate::cxx::handle::{refcounted_ptr_construct, refcounted_ptr_release};
use crate::fp::fp_misc::query_object_construct;
use crate::heap::veneers::operator_new;

/// # Safety
/// `object` and the installed base-constructor seam must support construction
/// of a writable 0xe8-byte controller. On a 64-bit host, object+0xbc must be
/// pointer-aligned for the existing StringObject port. The query constructor
/// must return an implementation suitable for the refcounted handle family.
/// Allocation failures are deliberately not guarded, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn query_context_controller_construct(object: *mut u8) -> *mut u8 {
    let query = query_object_construct(operator_new(0x48), 0, 0);
    let mut handle = core::ptr::null_mut();
    refcounted_ptr_construct(&mut handle, query as usize, 0);
    let object = kinded_controller_construct(object, &mut handle, 20, 0, 0, 0);
    refcounted_ptr_release(&mut handle);
    object.cast::<u32>().write(0x089a_2ce8);
    context_scope_init(object.add(0xd0), core::ptr::null_mut(), 0).sub(0xd0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::kinded_controller::{KindedControllerOps, KINDED_CONTROLLER_OPS};
    use crate::cxx::handle::{refcounted_body_acquire, RefcountedBody};
    use crate::fp::fp_misc::QUERY_OBJECT_CONSTRUCT;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, free_log};

    #[repr(C, align(8))]
    struct Storage([u8; 0x200]);
    static mut BODY_ALLOCATION: *mut u8 = core::ptr::null_mut();
    static mut BASE_RETURN: *mut u8 = core::ptr::null_mut();
    static mut NULL_QUERY: bool = false;

    unsafe extern "C" fn construct_query(query: *mut u8, _: u32, _: u32) -> *mut u8 {
        set_alloc_ret(core::ptr::addr_of!(BODY_ALLOCATION).read());
        if core::ptr::addr_of!(NULL_QUERY).read() { core::ptr::null_mut() } else { query }
    }

    unsafe extern "C" fn retain_in_base(
        object: *mut u8, slot: *mut *mut RefcountedBody, _: *const u8,
    ) -> *mut u8 {
        let alternate = core::ptr::addr_of!(BASE_RETURN).read();
        let object = if alternate.is_null() { object } else { alternate };
        refcounted_body_acquire(object.add(0xb4).cast(), slot.read());
        object
    }

    struct Restore(usize, KindedControllerOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(QUERY_OBJECT_CONSTRUCT).write(self.0);
                core::ptr::addr_of_mut!(KINDED_CONTROLLER_OPS).write(self.1);
            }
        }
    }

    #[test]
    fn construction_retains_query_and_initializes_only_returned_object() {
        let _base_lock = crate::app::kinded_controller::tests::seam_lock();
        let _heap_lock = mock_heap();
        unsafe {
            let _restore = Restore(
                core::ptr::addr_of!(QUERY_OBJECT_CONSTRUCT).read(),
                core::ptr::addr_of!(KINDED_CONTROLLER_OPS).read(),
            );
            core::ptr::addr_of_mut!(QUERY_OBJECT_CONSTRUCT).write(construct_query as usize);
            core::ptr::addr_of_mut!(KINDED_CONTROLLER_OPS).write(KindedControllerOps {
                construct_base: retain_in_base,
            });
            for null_query in [false, true] {
                for redirect in [false, true] {
                    let mut input = Storage([0xa5; 0x200]);
                    let mut alternate = Storage([0xa5; 0x200]);
                    let mut query = Storage([0xa5; 0x200]);
                    let mut body = core::mem::MaybeUninit::<RefcountedBody>::uninit();
                    let input_ptr = input.0.as_mut_ptr().add(4);
                    let alternate_ptr = alternate.0.as_mut_ptr().add(4);
                    core::ptr::addr_of_mut!(BODY_ALLOCATION).write(body.as_mut_ptr().cast());
                    core::ptr::addr_of_mut!(BASE_RETURN).write(
                        if redirect { alternate_ptr } else { core::ptr::null_mut() },
                    );
                    core::ptr::addr_of_mut!(NULL_QUERY).write(null_query);
                    set_alloc_ret(query.0.as_mut_ptr());
                    let result = query_context_controller_construct(input_ptr);
                    assert_eq!(result, if redirect { alternate_ptr } else { input_ptr });
                    let retained = result.add(0xb4).cast::<*mut RefcountedBody>().read();
                    if null_query {
                        assert!(retained.is_null());
                    } else {
                        assert_eq!(retained, body.as_mut_ptr());
                        assert_eq!((*retained).refcount, 1);
                        assert_eq!((*retained).opaque0, query.0.as_mut_ptr() as usize);
                        assert!((*retained).mutex.is_null());
                    }
                    assert_eq!(result.cast::<u32>().read(), 0x089a_2ce8);
                    assert_eq!(core::slice::from_raw_parts(result.add(0xc4), 6), &[0, 0, 1, 20, 0, 0]);
                    assert_eq!(result.add(0xcc).cast::<u32>().read(), 0);
                    assert_eq!(result.add(0xd0).cast::<u32>().read(), 0x089a_6600);
                    assert_eq!(core::slice::from_raw_parts(result.add(0xd4), 13), &[0; 13]);
                    assert_eq!(core::slice::from_raw_parts(result.add(0xe1), 7), &[0xa5; 7]);
                    assert_eq!(free_log().0, 0, "the base owns the remaining reference");
                    if redirect { assert_eq!(input.0, [0xa5; 0x200]); }
                    assert_eq!(query.0, [0xa5; 0x200]);
                }
            }
        }
    }
}

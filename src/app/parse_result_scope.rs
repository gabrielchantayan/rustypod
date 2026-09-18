//! `parse_result_scope_destroy` — destruction of the 0x38-byte parser scope
//! whose parser-result member is at +0x34.
//!
//! The paired constructor at 0x081d5e2c initializes the scope's +0x20
//! subobject and then calls `parse_result_init` for its final four bytes.
//! This destructor only calls the result record's trivial destructor, then
//! returns the original scope pointer.
use crate::app::parse_result::parse_result_destroy;

#[inline(always)]
unsafe fn destroy_embedded_result(record: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let callee: unsafe extern "C" fn(*mut u8) -> *mut u8 = parse_result_destroy;
        core::ptr::read_volatile(&callee)(record)
    }

    #[cfg(not(target_os = "none"))]
    {
        parse_result_destroy(record)
    }
}

/// parse_result_scope_destroy — original: `FUN_081d5e54` @ 0x081d5e54
/// (20 bytes; **4 plain `bl` call sites, 0 predicated `bl` call sites**,
/// binary-scanned from `osos.dec`).
///
/// The exact extent is 0x081d5e54..0x081d5e67: `push {r4,lr}; add r0,r0,#0x34;
/// bl 0x08283178; sub r0,r0,#0x34; pop {r4,pc}`. The next real function starts
/// at 0x081d5e68 with `push {r4,lr}`. It invokes [`parse_result_destroy`] on
/// the embedded parser-result record at +0x34, then rebases its preserved
/// return value back to the enclosing parser scope. The result destructor is
/// empty, so this reads and writes no memory, but its r0 pass-through is
/// required by the following subtraction.
///
/// Deliberate deviations: wrapping pointer arithmetic represents ARM's
/// register-only add/sub sequence even for a NULL or otherwise non-dereferenceable
/// scope pointer. On firmware builds the established callee is loaded
/// volatily before invocation so LLVM cannot erase this real call boundary;
/// this changes the direct `bl` to an indirect `blx`, but neither function
/// dereferences the scope address.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parse_result_scope_destroy(scope: *mut u8) -> *mut u8 {
    const RESULT_OFFSET: usize = 0x34;

    destroy_embedded_result(scope.wrapping_add(RESULT_OFFSET)).wrapping_sub(RESULT_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destroys_only_the_embedded_result_and_rebases_to_scope() {
        let mut scope = [0xa5u8; 0x38];
        let this = scope.as_mut_ptr();
        let before = scope;

        let returned = unsafe { parse_result_scope_destroy(this) };

        assert_eq!(returned, this, "the post-call subtraction restores this");
        assert_eq!(scope, before, "the embedded trivial destructor does not mutate the scope");
    }

    #[test]
    fn null_scope_round_trips_without_dereferencing() {
        assert!(unsafe { parse_result_scope_destroy(core::ptr::null_mut()) }.is_null());
    }
}

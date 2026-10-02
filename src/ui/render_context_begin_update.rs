//! Empty render-context pre-update hook.
//!
//! RetailOS `FUN_0828dccc` at **0x0828dccc**, exactly 4 bytes: raw
//! `osos.dec` contains only `0xe12fff1e` (`bx lr`); the next real function
//! starts at 0x0828dcd0. Independent whole-image A32 BL decoding finds
//! zero plain and two predicated inbound calls (`blne` at 0x08158428 and
//! 0x0826ea60). The body has no calls. No aligned image word references
//! this address, so there is no observed vtable entry.
//!
//! Both callers pass owner +0x3c's render-context pointer before their
//! update and call 0x0828da34 afterward. This hook immediately returns,
//! touching no memory and leaving r0 unchanged. The semantic name describes
//! that call ordering, not an inferred locking or destructor operation.
//!
//! Deliberate deviations: none in memory effects or r0. The pointer return
//! explicitly preserves the raw register value even though both observed
//! callers ignore it. Other caller-saved registers and flags are not part
//! of the C ABI contract.

/// Return the render context unchanged without accessing it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn render_context_begin_update(context: *mut u8) -> *mut u8 {
    context
}

#[cfg(test)]
mod tests {
    use super::render_context_begin_update;

    #[test]
    fn null_and_unaligned_nonobject_pointers_pass_through() {
        for address in [0usize, 1, 3, 0x0828_dccc, usize::MAX] {
            let context = address as *mut u8;
            assert_eq!(render_context_begin_update(context), context);
        }
    }

    #[test]
    fn context_storage_is_unchanged() {
        let mut context = [0xa5u8; 0x100];
        let before = context;
        let pointer = context.as_mut_ptr();
        assert_eq!(render_context_begin_update(pointer), pointer);
        assert_eq!(context, before);
    }
}

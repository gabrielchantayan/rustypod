//! `dispatch_opaque_node_context` — original `FUN_080034a8` @ 0x080034a8.
//!
//! Raw `osos.dec` words establish the true eight-byte extent
//! `0x080034a8..0x080034af`: `ldr pc, [pc, #-4]` (`0xe51ff004`) followed by
//! literal target `0x082cbb54`; 0x080034b0 starts the next distinct veneer.
//! Ghidra's reported 44-byte indirect call incorrectly absorbs adjacent
//! veneers and omits their literal words. Whole-image ARM decoding finds four
//! inbound plain `bl` callers (0x080007ec, 0x080010ac, 0x08001190, and
//! 0x08001458) and no inbound predicated `bl` calls.
//!
//! # Algorithm
//!
//! Tail-transfer the recovered `(node, context)` ABI to opaque retail target
//! 0x082cbb54, preserving its r0 result.
//!
//! # Deliberate deviations
//!
//! The target is not semantically identified or ported. ARM builds retain the
//! literal veneer exactly; host builds use an installable volatile seam. The
//! two-argument ABI is established by every caller and by the target's first
//! instructions, which dereference `context + 12` before any other use.

/// Fixed `ldr pc, [pc, #-4]` instruction at 0x080034a8.
pub const DISPATCH_OPAQUE_NODE_CONTEXT_INSN: u32 = 0xe51f_f004;

/// Literal target word at 0x080034ac.
pub const DISPATCH_OPAQUE_NODE_CONTEXT_TARGET: usize = 0x082c_bb54;

/// ABI recovered for the opaque retail node/context dispatch target.
pub type OpaqueNodeContextDispatch = unsafe extern "C" fn(*mut u8, *mut u8) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_opaque_node_context_dispatch(_node: *mut u8, _context: *mut u8) -> u32 {
    0
}

/// Host-only callback replacing the fixed retail target address.
#[cfg(not(target_arch = "arm"))]
pub static mut OPAQUE_NODE_CONTEXT_DISPATCH: OpaqueNodeContextDispatch = missing_opaque_node_context_dispatch;

/// Tail-calls the unported retail node/context dispatch target.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_opaque_node_context(node: *mut u8, context: *mut u8) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_NODE_CONTEXT_DISPATCH))(node, context) }
}

// A literal veneer remains reachable after this code moves into the patch
// payload and preserves r0-r3, lr, and the retail target's return value.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl dispatch_opaque_node_context
    .type dispatch_opaque_node_context, %function
dispatch_opaque_node_context:
    ldr     pc, 1f
1:  .word   0x082cbb54
    .size dispatch_opaque_node_context, . - dispatch_opaque_node_context
"#
);

#[cfg(test)]
mod tests {
    use super::{
        DISPATCH_OPAQUE_NODE_CONTEXT_INSN, DISPATCH_OPAQUE_NODE_CONTEXT_TARGET,
        OPAQUE_NODE_CONTEXT_DISPATCH, OpaqueNodeContextDispatch, dispatch_opaque_node_context,
    };
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED: (*mut u8, *mut u8) = (core::ptr::null_mut(), core::ptr::null_mut());

    unsafe extern "C" fn recording_target(node: *mut u8, context: *mut u8) -> u32 {
        unsafe { OBSERVED = (node, context) };
        if node.is_null() || context.is_null() { 0x0bad_f00d } else { 0x1234_5678 }
    }

    struct TargetRestore(OpaqueNodeContextDispatch);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { OPAQUE_NODE_CONTEXT_DISPATCH = self.0 };
        }
    }

    #[test]
    fn forwards_both_recovered_arguments_and_result() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = OPAQUE_NODE_CONTEXT_DISPATCH;
            OPAQUE_NODE_CONTEXT_DISPATCH = recording_target;
            OBSERVED = (core::ptr::null_mut(), core::ptr::null_mut());
            TargetRestore(previous)
        };
        let mut node = [0u8; 4];
        let mut context = [0u8; 16];
        let result = unsafe { dispatch_opaque_node_context(node.as_mut_ptr(), context.as_mut_ptr()) };
        assert_eq!(result, 0x1234_5678);
        assert_eq!(unsafe { OBSERVED }, (node.as_mut_ptr(), context.as_mut_ptr()));
    }

    #[test]
    fn forwards_null_arguments_without_a_veneer_guard() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = OPAQUE_NODE_CONTEXT_DISPATCH;
            OPAQUE_NODE_CONTEXT_DISPATCH = recording_target;
            TargetRestore(previous)
        };
        let result = unsafe { dispatch_opaque_node_context(core::ptr::null_mut(), core::ptr::null_mut()) };
        assert_eq!(result, 0x0bad_f00d);
        assert_eq!(unsafe { OBSERVED }, (core::ptr::null_mut(), core::ptr::null_mut()));
    }

    #[test]
    fn records_the_verified_veneer_words_and_distinct_entry() {
        assert_eq!(DISPATCH_OPAQUE_NODE_CONTEXT_INSN, 0xe51f_f004);
        assert_eq!(DISPATCH_OPAQUE_NODE_CONTEXT_TARGET, 0x082c_bb54);
        assert_ne!(dispatch_opaque_node_context as *const (), recording_target as *const ());
    }
}

//! `parser_stack_pop` — original: `FUN_0811ddc0` @ `0x0811ddc0` (60 bytes;
//! `0x0811ddc0..0x0811ddfc`).
//!
//! Raw ARM establishes the boundary: `0x0811ddfc` is a distinct function
//! beginning with `cmp r0, #0`. Decoding every inbound ARM branch finds three
//! plain direct `bl` callers (`0x08117e80`, `0x08119a24`, and `0x08119a48`) and
//! zero predicated direct `bl` callers. The body makes one direct `bl` to the
//! unresolved item lookup at `0x082987b4` and one register-indirect `blx`
//! through vtable slot `+0x2c`.
//!
//! # Algorithm
//!
//! Retrieves the stack item at `count - 1`, then invokes the stack object's
//! vtable `+0x2c` method with that same index to remove it. The retrieved item
//! is returned even though the removal method's return value is discarded.
//!
//! # Deliberate deviations
//!
//! `0x082987b4` is not yet ported. Target builds make its verified typed
//! known-address call; host builds use an injectable seam. The target's
//! vtable dispatch retains four-byte slot addressing, while host tests use a
//! native-width operation table.

const RETAIL_STACK_ITEM_LOOKUP: usize = 0x0829_87b4;
const VTABLE_REMOVE_AT_OFFSET: usize = 0x2c;

type StackItemLookup = unsafe extern "C" fn(*mut u8, i32) -> *mut u8;
type StackRemoveAt = unsafe extern "C" fn(*mut u8, i32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pop(stack: *mut u8) -> *mut u8 {
    let count = stack.add(4).cast::<i32>().read();
    let index = count.wrapping_sub(1);
    let lookup: StackItemLookup = core::mem::transmute(RETAIL_STACK_ITEM_LOOKUP);
    let item = lookup(stack, index);
    let vtable = stack.cast::<*const u8>().read();
    let remove: StackRemoveAt = vtable.add(VTABLE_REMOVE_AT_OFFSET).cast::<StackRemoveAt>().read();
    remove(stack, index);
    item
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ParserStackPopOps {
    pub item_lookup: StackItemLookup,
    pub remove_at: StackRemoveAt,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_item_lookup(_stack: *mut u8, _index: i32) -> *mut u8 {
    panic!("install parser stack pop host operations before calling")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_remove_at(_stack: *mut u8, _index: i32) {
    panic!("install parser stack pop host operations before calling")
}

/// Host seam for the unresolved lookup and runtime vtable dispatch.
#[cfg(not(target_os = "none"))]
pub static mut PARSER_STACK_POP_OPS: ParserStackPopOps = ParserStackPopOps {
    item_lookup: missing_item_lookup,
    remove_at: missing_remove_at,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pop(stack: *mut u8) -> *mut u8 {
    let count = stack.add(4).cast::<i32>().read_unaligned();
    let index = count.wrapping_sub(1);
    let ops = core::ptr::addr_of!(PARSER_STACK_POP_OPS).read_volatile();
    let item = (ops.item_lookup)(stack, index);
    (ops.remove_at)(stack, index);
    item
}

/// Returns and removes the parser stack's final item.
///
/// # Safety
///
/// `stack` must address the retail stack object. Its count is at `+4`; the
/// unresolved item lookup and vtable `+0x2c` removal method must accept the
/// resulting signed index.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parser_stack_pop(stack: *mut u8) -> *mut u8 {
    pop(stack)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUP_CALL: (*mut u8, i32) = (core::ptr::null_mut(), 0);
    static mut REMOVE_CALL: (*mut u8, i32) = (core::ptr::null_mut(), 0);
    static mut LOOKUP_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_lookup(stack: *mut u8, index: i32) -> *mut u8 {
        LOOKUP_CALL = (stack, index);
        LOOKUP_RESULT
    }

    unsafe extern "C" fn recording_remove(stack: *mut u8, index: i32) {
        REMOVE_CALL = (stack, index);
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
        original: ParserStackPopOps,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(PARSER_STACK_POP_OPS).write_volatile(self.original) };
        }
    }

    fn install_ops(result: *mut u8) -> OpsGuard {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let original = addr_of!(PARSER_STACK_POP_OPS).read_volatile();
            addr_of_mut!(PARSER_STACK_POP_OPS).write_volatile(ParserStackPopOps {
                item_lookup: recording_lookup,
                remove_at: recording_remove,
            });
            LOOKUP_RESULT = result;
            LOOKUP_CALL = (core::ptr::null_mut(), 0);
            REMOVE_CALL = (core::ptr::null_mut(), 0);
            OpsGuard { _lock: lock, original }
        }
    }

    #[test]
    fn pops_last_item_and_returns_lookup_result_after_removal() {
        let mut stack = [0u32; 2];
        stack[1] = 3;
        let mut item = 0u8;
        let _ops = install_ops(addr_of_mut!(item));

        assert_eq!(unsafe { parser_stack_pop(stack.as_mut_ptr().cast()) }, addr_of_mut!(item));
        unsafe {
            assert_eq!(LOOKUP_CALL, (stack.as_mut_ptr().cast(), 2));
            assert_eq!(REMOVE_CALL, (stack.as_mut_ptr().cast(), 2));
        }
    }

    #[test]
    fn empty_stack_preserves_wrapped_negative_index_for_both_calls() {
        let mut stack = [0u32; 2];
        let _ops = install_ops(core::ptr::null_mut());

        assert!(unsafe { parser_stack_pop(stack.as_mut_ptr().cast()) }.is_null());
        unsafe {
            assert_eq!(LOOKUP_CALL, (stack.as_mut_ptr().cast(), -1));
            assert_eq!(REMOVE_CALL, (stack.as_mut_ptr().cast(), -1));
        }
    }
}

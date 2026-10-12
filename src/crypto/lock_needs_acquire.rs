//! Crypto lock acquisition eligibility.
//!
//! `crypto_lock_needs_acquire` — `FUN_08043b28` @ 0x08043b28.
//! True extent [0x08043b28, 0x08043b94): 108 bytes (104 code, singleton
//! literal 0x08a0ec84 at 0x08043b90). Raw A32 verifies three outgoing plain
//! BLs, zero predicated BLs; two incoming plain BLs, zero predicated BLs.
//! Return zero when flag bit 0 is clear. Otherwise bracket the predicate in
//! resource 20 operations 5/6: return one if flag bit 1 is set or the current
//! context differs from the owner at +0x18. Reload flags after operation 5
//! and owner after the context callback; always perform operation 6.
//!
//! Deviations: host storage replaces the fixed singleton. Target calls the
//! verified stock dispatcher/context entries, retaining their live descriptor
//! rather than requiring installation of the Rust service table. Hosts reuse
//! those existing Rust seams. Volatile word reads preserve callback ordering.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_LOCK_STATE: [u32; 7] = [0; 7];

#[inline(always)]
unsafe fn state() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x08a0_ec84 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_LOCK_STATE).cast() }
}

#[inline(always)]
unsafe fn dispatch(op: u32) {
    #[cfg(target_os = "none")]
    let call: unsafe extern "C" fn(u32, i32, u32, u32) = core::mem::transmute(0x0804_3b94usize);
    #[cfg(not(target_os = "none"))]
    let call = crate::kernel::resource_op::resource_op_dispatch;
    call(op, 20, 0, 0);
}

#[inline(always)]
unsafe fn context_id() -> u32 {
    #[cfg(target_os = "none")]
    let call: unsafe extern "C" fn() -> u32 = core::mem::transmute(0x0804_4174usize);
    #[cfg(not(target_os = "none"))]
    let call = crate::kernel::resource_op::current_context_id;
    call()
}

/// Whether the enabled crypto lock needs acquisition by this context.
///
/// # Safety
/// The firmware singleton and descriptor callbacks must be initialized;
/// callers must obey the firmware's synchronization protocol.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crypto_lock_needs_acquire() -> u32 {
    let state = state();
    if ptr::read_volatile(state) & 1 == 0 { return 0; }
    dispatch(5);
    let needs_acquire = if ptr::read_volatile(state) & 2 != 0 {
        true
    } else {
        let current = context_id();
        current != ptr::read_volatile(state.add(6))
    };
    dispatch(6);
    needs_acquire as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::resource_op::{RESOURCE_OP_HOOKS, RESOURCE_OP_HOOKS_TEST_LOCK};

    static mut ACQUIRE_FLAGS: u32 = 0;
    static mut CURRENT: u32 = 0;
    static mut CHANGE_OWNER: bool = false;
    static mut TRACE: u32 = 0;

    unsafe extern "C" fn lock_op(op: u32, resource: i32, a: u32, b: u32) {
        assert_eq!((resource, a, b), (20, 0, 0));
        TRACE = TRACE * 10 + op;
        if op == 5 { state().write(ACQUIRE_FLAGS); }
        else { assert_eq!(op, 6); state().write(0); }
    }

    unsafe extern "C" fn current() -> u32 {
        TRACE = TRACE * 10 + 1;
        if CHANGE_OWNER { state().add(6).write(CURRENT); }
        CURRENT
    }

    #[test]
    fn eligibility_and_callback_mutations() {
        let _guard = RESOURCE_OP_HOOKS_TEST_LOCK.lock();
        unsafe {
            let saved = ptr::read(ptr::addr_of!(RESOURCE_OP_HOOKS));
            RESOURCE_OP_HOOKS.static_op = Some(lock_op);
            RESOURCE_OP_HOOKS.context_id = Some(current);
            // Disabled, including bit 1 alone: no callback or owner access.
            for flags in [0, 2, 0xffff_fffe] {
                state().write(flags); TRACE = 0;
                assert_eq!(crypto_lock_needs_acquire(), 0);
                assert_eq!({ TRACE }, 0);
            }
            // Result is computed under the bracket and survives release's mutation.
            for (flags, owner, current_id, change_owner, result, trace) in [
                (3, 7, 7, false, 1, 56),
                (1, 7, 7, false, 0, 516),
                (1, 7, 8, false, 1, 516),
                (1, 0xffff_ffff, 0xffff_ffff, false, 0, 516),
                (1, 7, 8, true, 0, 516),
                (0, 7, 8, false, 1, 516),
            ] {
                state().write(1); state().add(6).write(owner);
                ACQUIRE_FLAGS = flags; CURRENT = current_id;
                CHANGE_OWNER = change_owner; TRACE = 0;
                assert_eq!(crypto_lock_needs_acquire(), result);
                assert_eq!({ TRACE }, trace);
                assert_eq!(state().read(), 0);
            }
            ptr::write(ptr::addr_of_mut!(RESOURCE_OP_HOOKS), saved);
        }
    }
}

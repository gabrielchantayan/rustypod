//! OpenSSL's lock-bracketed reference-count update.
//!
//! Port: `crypto_add_lock` — `FUN_08043828` @ 0x08043828 (132 bytes:
//! 128 bytes of code plus the services-descriptor literal 0x08a0e93c @
//! 0x080438ac). The next separately linked function,
//! `resource_registry_release`, starts at 0x080438b0, so Ghidra's 132-byte
//! extent is exact. **12 unconditional `bl` call sites**, with no predicated
//! `bl` forms and no tail `b` sites, verified by decoding every ARM B/BL word
//! in `osos.dec`. No data word holds 0x08043828, so it is not a virtual slot.
//!
//! # Decoded from raw ARM at 0x08043828
//!
//! ```text
//! ldr   ip, [services_descriptor + 0x0c]
//! cmp   ip, #0
//! blxne ip                                      ; whole-operation override
//! moveq r0, #9
//! moveq r1, lock_type
//! moveq r2, file
//! bl    resource_op_dispatch
//! ldreq r0, [pointer]
//! addeq r4, r0, amount
//! streq r4, [pointer]
//! moveq r0, #10
//! bleq  resource_op_dispatch
//! ```
//!
//! The override receives all five arguments and replaces the operation. With
//! the stock NULL descriptor slot, this takes resource operation 9, stores
//! `pointer.wrapping_add(amount)`, then takes resource operation 10. `file`
//! and `line` ride through both resource calls unchanged as their final two
//! arguments.
//!
//! Deliberate deviation: services-descriptor slot +0x0c lives in
//! [`crate::kernel::resource_op::RESOURCE_OP_HOOKS`] rather than target RAM;
//! Rust calls the resource dispatcher normally where ARM uses `bl`, and the
//! wrapping arithmetic names ARM's modulo-2^32 `add` explicitly.

use crate::kernel::resource_op::{resource_op_dispatch, ResourceOpHooks, RESOURCE_OP_HOOKS};

/// CRYPTO_add_lock — original: `FUN_08043828` @ 0x08043828 (132 bytes; 12
/// unconditional `bl` call sites, no predicated forms, binary-verified).
///
/// If the services descriptor's `add_lock_callback` is installed, forwards
/// the complete operation to it and returns its answer. Otherwise brackets a
/// wrapping update of `*pointer` in `resource_op_dispatch(9, lock_type,
/// file, line)` and `(10, lock_type, file, line)`, returning the stored value.
///
/// # Safety
///
/// `pointer` must point to a writable aligned `i32`. The original has no NULL
/// guard. An installed callback must obey the declared C ABI and may define
/// the entire update itself.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crypto_add_lock(
    pointer: *mut i32,
    amount: i32,
    lock_type: i32,
    file: *const u8,
    line: i32,
) -> i32 {
    let hooks: ResourceOpHooks = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_OP_HOOKS))
    };
    if let Some(callback) = hooks.add_lock_callback {
        return unsafe { callback(pointer, amount, lock_type, file, line) };
    }

    let file_word = file as usize as u32;
    let line_word = line as u32;
    unsafe { resource_op_dispatch(9, lock_type, file_word, line_word) };
    let updated = unsafe { (*pointer).wrapping_add(amount) };
    unsafe { *pointer = updated };
    unsafe { resource_op_dispatch(10, lock_type, file_word, line_word) };
    updated
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::resource_op::{
        missing_registry_acquire, missing_registry_release, ResourceOpHooks,
        RESOURCE_OP_HOOKS_TEST_LOCK,
    };
    use parking_lot::MutexGuard;
    use std::vec::Vec;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        ResourceOp(u32, i32, u32, u32),
        Callback(usize, i32, i32, usize, i32),
    }

    static mut EVENTS: Vec<Event> = Vec::new();
    static mut CALLBACK_RESULT: i32 = 0;

    unsafe extern "C" fn recording_resource_op(op: u32, resource: i32, arg0: u32, arg1: u32) {
        unsafe { (*core::ptr::addr_of_mut!(EVENTS)).push(Event::ResourceOp(op, resource, arg0, arg1)) };
    }

    unsafe extern "C" fn recording_callback(
        pointer: *mut i32,
        amount: i32,
        lock_type: i32,
        file: *const u8,
        line: i32,
    ) -> i32 {
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Callback(
                pointer as usize, amount, lock_type, file as usize, line,
            ));
            CALLBACK_RESULT
        }
    }

    struct HooksGuard {
        #[allow(dead_code)]
        lock: MutexGuard<'static, ()>,
        saved: ResourceOpHooks,
    }

    impl Drop for HooksGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(self.saved);
                (*core::ptr::addr_of_mut!(EVENTS)).clear();
            }
        }
    }

    fn install(
        static_op: Option<unsafe extern "C" fn(u32, i32, u32, u32)>,
        add_lock_callback: Option<crate::kernel::resource_op::AddLockCallback>,
    ) -> HooksGuard {
        let lock = RESOURCE_OP_HOOKS_TEST_LOCK.lock();
        let saved = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_OP_HOOKS)) };
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            CALLBACK_RESULT = 0;
            core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(ResourceOpHooks {
                static_op,
                add_lock_callback,
                context_id: None,
                object_op: None,
                acquire: missing_registry_acquire,
                release: missing_registry_release,
            });
        }
        HooksGuard { lock, saved }
    }

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    #[test]
    fn fallback_brackets_the_wrapping_store_and_forwards_debug_arguments() {
        let _guard = install(Some(recording_resource_op), None);
        let mut count = 7;
        let file = 0xfeed_faceusize as *const u8;

        let result = unsafe { crypto_add_lock(&mut count, -9, 10, file, -2) };

        assert_eq!(result, -2);
        assert_eq!(count, -2);
        assert_eq!(
            events(),
            std::vec![
                Event::ResourceOp(9, 10, 0xfeed_face, u32::MAX - 1),
                Event::ResourceOp(10, 10, 0xfeed_face, u32::MAX - 1),
            ],
            "op 9 must precede the store and op 10 must follow it"
        );
    }

    #[test]
    fn fallback_uses_arm_wrapping_addition() {
        let _guard = install(None, None);
        let mut count = i32::MAX;

        let result = unsafe { crypto_add_lock(&mut count, 1, i32::MIN, core::ptr::null(), 0) };

        assert_eq!(result, i32::MIN);
        assert_eq!(count, i32::MIN);
        assert!(events().is_empty(), "the stock NULL static-resource slot is a no-op");
    }

    #[test]
    fn descriptor_callback_replaces_the_entire_operation() {
        let _guard = install(Some(recording_resource_op), Some(recording_callback));
        let mut count = 42;
        let file = 0x1234_5678usize as *const u8;
        unsafe { CALLBACK_RESULT = -77 };

        let result = unsafe { crypto_add_lock(&mut count, -1, 9, file, 321) };

        assert_eq!(result, -77);
        assert_eq!(count, 42, "the fallback store must not run under an override");
        assert_eq!(
            events(),
            std::vec![Event::Callback(
                core::ptr::addr_of_mut!(count) as usize,
                -1,
                9,
                file as usize,
                321,
            )],
            "the callback receives all five untouched arguments and no resource operation"
        );
    }
}

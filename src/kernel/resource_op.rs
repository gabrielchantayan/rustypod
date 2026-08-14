//! The RAM-side resource-operation dispatcher over the services
//! descriptor @ 0x08a0e93c.
//!
//! `resource_op_dispatch` @ 0x08043b94 is the single entry every caller in
//! the image uses to run a lock/unlock-style operation on a numbered
//! resource. Callers wrap critical sections in matched pairs — op 9 before
//! the section and op 10 after it, or op 5 / op 6 for the shorter
//! ownership probes — always with the same small resource id, and always
//! with `arg0`/`arg1` zero:
//!
//! ```text
//! 0x080b6ba4:  resource_op_dispatch(9, 1, 0, 0);
//!              counter = *slot; *slot = counter + 1;
//!              resource_op_dispatch(10, 1, 0, 0);
//! 0x08092504:  resource_op_dispatch(5, 0x13, 0, 0);
//!              owned = current_context_id() == descriptor[5];
//!              resource_op_dispatch(6, 0x13, 0, 0);
//!              if (!owned) resource_op_dispatch(9, 0x12, 0, 0);
//! ```
//!
//! The sign of `resource` selects the handler, and that is the whole
//! function: non-negative ids are *static* resources handled by descriptor
//! slot +0x08; negative ids are handles into the descriptor's registry of
//! dynamically created resources (slot +0x04, a refcounted vector), which
//! are resolved to an object first and handled by slot +0x18.
//!
//! Neighbours over the same descriptor, all still unported:
//!
//! - 0x08043a6c — registry acquire: maps `resource` to the vector index
//!   `~resource`, bumps the object's refcount and returns it (itself
//!   bracketed by `resource_op_dispatch(9, 0x1d, 0, 0)` /
//!   `(10, 0x1d, 0, 0)` around the vector access).
//! - 0x080438b0 — registry release: drops the refcount, and on the last
//!   reference erases the vector slot, runs the destroy hook (slot +0x1c)
//!   and hands the object to `traced_free` @ 0x08043994.
//! - 0x08044174 — current-context id: tail-calls slot +0x10, or returns 1
//!   when that slot is empty.

/// Function-pointer services this dispatcher reads out of the descriptor
/// @ 0x08043b94's literal pool points at (0x08a0e93c, the word @
/// 0x08043c14). Only two of the descriptor's slots are consulted here;
/// the port keeps them — plus the two registry entry points the negative
/// path branches to — in one hook table, the
/// [`crate::drivers::ata_cmd::TRACED_ALLOC_HOOKS`] pattern.
#[derive(Copy, Clone)]
pub struct ResourceOpHooks {
    /// Descriptor slot +0x08: the handler for static resources
    /// (`resource >= 0`), tail-called as `static_op(op, resource, arg0,
    /// arg1)`. `None` = the stock image's NULL slot, which makes the
    /// whole call a no-op.
    pub static_op: Option<unsafe extern "C" fn(op: u32, resource: i32, arg0: u32, arg1: u32)>,
    /// Descriptor slot +0x18: the handler for registered resources
    /// (`resource < 0`), called as `object_op(op, object, arg0, arg1)`
    /// with the *resolved object* in place of the id. `None` = the stock
    /// image's NULL slot, which makes the whole negative path a no-op —
    /// checked before the registry is ever touched.
    pub object_op: Option<unsafe extern "C" fn(op: u32, object: *mut u8, arg0: u32, arg1: u32)>,
    /// Registry acquire @ 0x08043a6c (a direct `bl`, not a descriptor
    /// slot): resolves a negative `resource` to its object and bumps its
    /// refcount. Returning NULL is fatal here — the original answers it
    /// with `bleq heap_panic`.
    pub acquire: unsafe extern "C" fn(resource: i32) -> *mut u8,
    /// Registry release @ 0x080438b0 (the original's tail branch): drops
    /// the refcount taken by `acquire`. Takes the raw `resource` id, not
    /// the object.
    pub release: unsafe extern "C" fn(resource: i32),
}

/// Default acquire stub: the registry is unported, so report "no such
/// resource" — the original's own miss result. Unreachable with the
/// default table, because `object_op` is `None` and the negative path
/// returns before the registry is consulted.
pub unsafe extern "C" fn missing_registry_acquire(_resource: i32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Default release stub: nothing was acquired, so there is nothing to
/// drop.
pub unsafe extern "C" fn missing_registry_release(_resource: i32) {}

/// Hook table for the descriptor's slots and the registry entry points.
/// Replace before first use on target; host tests install mocks via
/// `core::ptr::addr_of_mut!`.
pub static mut RESOURCE_OP_HOOKS: ResourceOpHooks = ResourceOpHooks {
    static_op: None,
    object_op: None,
    acquire: missing_registry_acquire,
    release: missing_registry_release,
};

/// Reads the hook table. Volatile so LLVM cannot constant-fold the load
/// to the default stubs, and so the second read below is a real re-read —
/// the original reloads slot +0x18 after `acquire` returns rather than
/// caching it (`ldr ip, [r4, #0x18]` @ 0x08043bcc).
#[inline(always)]
fn hooks() -> ResourceOpHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_OP_HOOKS)) }
}

/// resource_op_dispatch — original: `FUN_08043b94` @ 0x08043b94
/// (132 bytes: 128 bytes of code plus the descriptor pointer literal
/// 0x08a0e93c @ 0x08043c14, which Ghidra's 128-byte extent drops; the
/// next function, `traced_alloc`, starts at 0x08043c18). 74 `bl` +
/// 3 `bleq` = 77 `bl`-form call sites, plus 4 tail `b` = 81 total, all
/// binary-verified by decoding every B/BL word in osos.dec.
///
/// Runs operation `op` on resource `resource`. The sign of `resource` is
/// the whole dispatch (the original's `subs r5, r1, #0` / `bge`):
///
/// 1. `resource >= 0` — a static resource. Load slot +0x08; if it is
///    empty, return without doing anything; otherwise tail-call
///    `static_op(op, resource, arg0, arg1)` with the arguments untouched.
/// 2. `resource < 0` — a registered resource. Load slot +0x18; if it is
///    empty, return without touching the registry.
/// 3. Resolve the id: `object = acquire(resource)` (0x08043a6c). A NULL
///    object is fatal — the original answers it with
///    `bleq heap_panic` @ 0x08030f44, which does not return.
/// 4. Re-load slot +0x18 and call `object_op(op, object, arg0, arg1)` —
///    the object replaces the id in argument position 1, and `arg0`/
///    `arg1` ride through unchanged.
/// 5. Tail-branch to `release(resource)` (0x080438b0) with the *raw
///    negative id*, not the object.
///
/// Void: the original leaves r0 holding whatever the last path touched
/// (0 from the empty +0x18 slot, `op` from the empty +0x08 slot, the
/// tail callee's result otherwise) and no caller reads it.
///
/// Deviations: the descriptor slots and the two registry entry points
/// live in [`RESOURCE_OP_HOOKS`] (the
/// [`crate::drivers::ata_cmd::TRACED_ALLOC_HOOKS`] pattern) because the
/// registry itself is unported; the original's two tail branches are
/// plain calls (Rust has no guaranteed tail calls); and the re-loaded
/// +0x18 slot is called only when it is still installed, where the
/// original would `blx` a NULL slot — a crash the stock image never
/// reaches, since nothing clears the slot while a resource is held.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn resource_op_dispatch(op: u32, resource: i32, arg0: u32, arg1: u32) {
    if resource >= 0 {
        if let Some(static_op) = hooks().static_op {
            static_op(op, resource, arg0, arg1);
        }
        return;
    }
    if hooks().object_op.is_none() {
        return;
    }
    let object = (hooks().acquire)(resource);
    if object.is_null() {
        crate::heap::veneers::heap_panic();
    }
    // Re-read: the original reloads slot +0x18 after `acquire` returns.
    if let Some(object_op) = hooks().object_op {
        object_op(op, object, arg0, arg1);
    }
    (hooks().release)(resource);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    /// Serializes the tests that swap the global hook table.
    static HOOKS_LOCK: Mutex<()> = Mutex::new(());

    static mut STATIC_CALLS: usize = 0;
    static mut LAST_STATIC_ARGS: (u32, i32, u32, u32) = (0, 0, 0, 0);
    static mut OBJECT_CALLS: usize = 0;
    static mut LAST_OBJECT_ARGS: (u32, *mut u8, u32, u32) = (0, core::ptr::null_mut(), 0, 0);
    static mut SWAPPED_CALLS: usize = 0;
    static mut ACQUIRE_CALLS: usize = 0;
    static mut LAST_ACQUIRE_ID: i32 = 0;
    static mut ACQUIRE_RET: *mut u8 = core::ptr::null_mut();
    static mut RELEASE_CALLS: usize = 0;
    static mut LAST_RELEASE_ID: i32 = 0;
    /// Call order, so the acquire -> op -> release sequence is pinned.
    static mut TRACE: [u8; 8] = [0; 8];
    static mut TRACE_LEN: usize = 0;

    /// Opaque stand-in for a registry object; never dereferenced, the
    /// way the original only ever passes it through to slot +0x18.
    const OBJECT: usize = 0x5150_0000;

    unsafe fn record(tag: u8) {
        if TRACE_LEN < TRACE.len() {
            TRACE[TRACE_LEN] = tag;
            TRACE_LEN += 1;
        }
    }

    unsafe extern "C" fn mock_static_op(op: u32, resource: i32, arg0: u32, arg1: u32) {
        STATIC_CALLS += 1;
        LAST_STATIC_ARGS = (op, resource, arg0, arg1);
        record(b'S');
    }

    unsafe extern "C" fn mock_object_op(op: u32, object: *mut u8, arg0: u32, arg1: u32) {
        OBJECT_CALLS += 1;
        LAST_OBJECT_ARGS = (op, object, arg0, arg1);
        record(b'O');
    }

    /// Stands in for a slot +0x18 that changed while the registry call
    /// was running — used to prove the re-read.
    unsafe extern "C" fn swapped_object_op(_op: u32, _object: *mut u8, _arg0: u32, _arg1: u32) {
        SWAPPED_CALLS += 1;
        record(b'W');
    }

    unsafe extern "C" fn mock_acquire(resource: i32) -> *mut u8 {
        ACQUIRE_CALLS += 1;
        LAST_ACQUIRE_ID = resource;
        record(b'A');
        ACQUIRE_RET
    }

    /// `mock_acquire` plus the slot swap the re-read test needs.
    unsafe extern "C" fn acquire_and_swap_slot(resource: i32) -> *mut u8 {
        let ret = mock_acquire(resource);
        core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS)
            .cast::<ResourceOpHooks>()
            .write_volatile(ResourceOpHooks {
                object_op: Some(swapped_object_op),
                ..hooks()
            });
        ret
    }

    unsafe extern "C" fn mock_release(resource: i32) {
        RELEASE_CALLS += 1;
        LAST_RELEASE_ID = resource;
        record(b'R');
    }

    /// Resets the log, installs a fully mocked table and returns the
    /// lock guard.
    fn mock_hooks(
        static_op: Option<unsafe extern "C" fn(u32, i32, u32, u32)>,
        object_op: Option<unsafe extern "C" fn(u32, *mut u8, u32, u32)>,
        acquire: unsafe extern "C" fn(i32) -> *mut u8,
    ) -> std::sync::MutexGuard<'static, ()> {
        let guard = HOOKS_LOCK.lock().unwrap();
        unsafe {
            STATIC_CALLS = 0;
            LAST_STATIC_ARGS = (0, 0, 0, 0);
            OBJECT_CALLS = 0;
            LAST_OBJECT_ARGS = (0, core::ptr::null_mut(), 0, 0);
            SWAPPED_CALLS = 0;
            ACQUIRE_CALLS = 0;
            LAST_ACQUIRE_ID = 0;
            ACQUIRE_RET = OBJECT as *mut u8;
            RELEASE_CALLS = 0;
            LAST_RELEASE_ID = 0;
            TRACE = [0; 8];
            TRACE_LEN = 0;
            core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(ResourceOpHooks {
                static_op,
                object_op,
                acquire,
                release: mock_release,
            });
        }
        guard
    }

    unsafe fn trace() -> &'static [u8] {
        core::slice::from_raw_parts(core::ptr::addr_of!(TRACE).cast::<u8>(), TRACE_LEN)
    }

    #[test]
    fn non_negative_resource_reaches_the_static_slot_with_arguments_intact() {
        let _lock = mock_hooks(Some(mock_static_op), Some(mock_object_op), mock_acquire);
        unsafe {
            // The real call shapes: (9, id, 0, 0) / (10, id, 0, 0) lock
            // pairs, and the (5, 0x13) / (6, 0x13) ownership probes.
            for (op, resource) in [(9u32, 1i32), (10, 1), (5, 0x13), (6, 0x13), (9, 0x1d)] {
                let before = STATIC_CALLS;
                resource_op_dispatch(op, resource, 0, 0);
                assert_eq!(STATIC_CALLS, before + 1);
                assert_eq!(LAST_STATIC_ARGS, (op, resource, 0, 0));
            }
            // arg0/arg1 ride through untouched even though every stock
            // caller passes zero.
            resource_op_dispatch(9, 0x12, 0xdead_beef, 0x1234_5678);
            assert_eq!(LAST_STATIC_ARGS, (9, 0x12, 0xdead_beef, 0x1234_5678));
            assert_eq!(ACQUIRE_CALLS, 0, "the registry is for negative ids only");
            assert_eq!(RELEASE_CALLS, 0);
            assert_eq!(OBJECT_CALLS, 0);
        }
    }

    #[test]
    fn resource_zero_is_static_not_registered() {
        // `subs`/`bge`: zero takes the non-negative branch.
        let _lock = mock_hooks(Some(mock_static_op), Some(mock_object_op), mock_acquire);
        unsafe {
            resource_op_dispatch(9, 0, 0, 0);
            assert_eq!(STATIC_CALLS, 1);
            assert_eq!(LAST_STATIC_ARGS, (9, 0, 0, 0));
            assert_eq!(ACQUIRE_CALLS, 0);
        }
    }

    #[test]
    fn empty_static_slot_makes_the_call_a_no_op() {
        let _lock = mock_hooks(None, Some(mock_object_op), mock_acquire);
        unsafe {
            resource_op_dispatch(9, 1, 0, 0);
            assert_eq!(trace(), b"", "nothing runs when slot +0x08 is empty");
        }
    }

    #[test]
    fn negative_resource_acquires_dispatches_then_releases_by_id() {
        let _lock = mock_hooks(Some(mock_static_op), Some(mock_object_op), mock_acquire);
        unsafe {
            resource_op_dispatch(10, -3, 7, 8);
            assert_eq!(trace(), b"AOR", "acquire, then the op, then release");
            assert_eq!(LAST_ACQUIRE_ID, -3, "the raw id, not the vector index");
            // The object replaces the id in argument position 1.
            assert_eq!(LAST_OBJECT_ARGS, (10, OBJECT as *mut u8, 7, 8));
            // Release takes the id back, not the object.
            assert_eq!(LAST_RELEASE_ID, -3);
            assert_eq!(STATIC_CALLS, 0, "slot +0x08 is for non-negative ids");
        }
    }

    #[test]
    fn most_negative_resource_still_takes_the_registry_path() {
        let _lock = mock_hooks(Some(mock_static_op), Some(mock_object_op), mock_acquire);
        unsafe {
            for resource in [-1i32, -0x1d, i32::MIN] {
                let before = OBJECT_CALLS;
                resource_op_dispatch(9, resource, 0, 0);
                assert_eq!(OBJECT_CALLS, before + 1);
                assert_eq!(LAST_ACQUIRE_ID, resource);
                assert_eq!(LAST_RELEASE_ID, resource);
            }
            assert_eq!(STATIC_CALLS, 0);
        }
    }

    #[test]
    fn empty_object_slot_returns_before_touching_the_registry() {
        // The +0x18 guard sits *above* the acquire call, so a missing
        // handler must not take (or leak) a registry reference.
        let _lock = mock_hooks(Some(mock_static_op), None, mock_acquire);
        unsafe {
            resource_op_dispatch(9, -2, 0, 0);
            assert_eq!(trace(), b"", "no acquire, no release, no dispatch");
        }
    }

    #[test]
    fn object_slot_is_re_read_after_the_acquire() {
        // The original reloads `[r4, #0x18]` at 0x08043bcc instead of
        // reusing the value it guarded on, so a handler installed while
        // the registry call was running is the one that runs.
        let _lock = mock_hooks(
            Some(mock_static_op),
            Some(mock_object_op),
            acquire_and_swap_slot,
        );
        unsafe {
            resource_op_dispatch(9, -4, 0, 0);
            assert_eq!(trace(), b"AWR");
            assert_eq!(OBJECT_CALLS, 0, "the pre-acquire handler must not run");
            assert_eq!(SWAPPED_CALLS, 1);
            assert_eq!(RELEASE_CALLS, 1, "the release still runs");
        }
    }

    #[test]
    fn default_hooks_make_every_call_a_no_op() {
        let guard = HOOKS_LOCK.lock().unwrap();
        unsafe {
            let saved = hooks();
            core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(ResourceOpHooks {
                static_op: None,
                object_op: None,
                acquire: missing_registry_acquire,
                release: missing_registry_release,
            });
            // Both branches are safe with the stock NULL slots: the
            // negative path returns before it could hit the fatal
            // NULL-object check.
            resource_op_dispatch(9, 1, 0, 0);
            resource_op_dispatch(9, -1, 0, 0);
            core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(saved);
        }
        drop(guard);
    }
}

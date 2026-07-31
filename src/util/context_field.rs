//! task_ctx_field_0x30 — original: `FUN_0827233c` @ 0x0827233c (16 bytes;
//! 647 `bl` call sites, binary-scanned — the hottest 16-byte leaf in
//! 0x08200000..0x082fffff).
//!
//! A three-instruction accessor:
//!
//! ```text
//! push {r4, lr}
//! bl   0x080cb828        @ ctx = current_task_ctx_block()
//! ldr  r0, [r0, #0x30]   @ return ctx->+0x30
//! pop  {r4, pc}
//! ```
//!
//! The callee `FUN_080cb828` @ 0x080cb828 (20 bytes, 46 `bl` call sites)
//! is itself `node = kernel_running(); return node ? node->+0xc : 0` —
//! the current task's context block (ported as `current_task_ctx_block`
//! in kernel/task.rs, with `kernel_running` @ 0x0809444c ported in
//! kernel/sync_mutex.rs). So the whole chain is a two-level accessor
//! onto the kernel's task object graph: field +0x30 of the current
//! task's context block. What that field holds is not decoded — its
//! other writers live outside the ported set — so the function is
//! ported on observable behavior under the field-offset name. Its
//! 20-byte sibling @ 0x0827234c is the matching setter
//! (`mov r4, r0; bl 0x080cb828; str r4, [r0, #0x30]`), ported below
//! as [`task_ctx_set_field_0x30`].
//!
//! The original does NOT NULL-check the callee's result: with no
//! current task (kernel not started, or a bare-metal caller) the
//! `ldr [r0, #0x30]` reads from 0x30 and takes a data abort. Every
//! observed call site runs under the kernel, where the block exists;
//! the port keeps the unchecked load, so the same fault is reproduced
//! rather than masked.
//!
//! Deviation: the callee sits behind the [`CURRENT_TASK_CTX_BLOCK`]
//! dispatch slot (the util/inner_state.rs `INNER_MATERIALIZE_COUNT`
//! pattern) instead of a direct `bl 0x080cb828`, so host tests can
//! install a recording mock. The default stub models the callee's
//! known prefix exactly — `kernel_running()` (ported) as the name-node
//! pointer, then the context-block word at node+0x0c, or NULL — so on
//! target the slot is born behaviorally identical to the direct call;
//! it is retired when the slot is rewired to the ported callee itself.

/// Byte offset of the requested field inside the task context block.
const FIELD: usize = 0x30;

/// Byte offset of the context-block pointer inside the current task's
/// name node (0x080cb828's `ldrne r0, [r0, #0xc]`).
const NODE_CTX: usize = 0x0c;

/// Default [`CURRENT_TASK_CTX_BLOCK`] stub: the known prefix of the
/// unported-in-this-module callee `FUN_080cb828` @ 0x080cb828 —
/// `kernel_running()`'s "task id" is really the current task's name-node
/// pointer (kernel/task.rs `current_task_ctx_block` establishes this);
/// return the node's context-block word at +0x0c, or NULL when the
/// kernel reports no task (the `cmp r0, #0; ldrne` guard). Exact for
/// every state the firmware observes; host tests swap in a mock.
unsafe extern "C" fn current_task_ctx_block_stub() -> *mut u8 {
    let node = crate::kernel::sync_mutex::kernel_running();
    if node == 0 {
        core::ptr::null_mut()
    } else {
        ((node as usize as *const u8).add(NODE_CTX) as *const *mut u8).read()
    }
}

/// Indirect dispatch for the current-task context-block getter
/// `FUN_080cb828` @ 0x080cb828 (the util/inner_state.rs
/// `INNER_MATERIALIZE_COUNT` pattern). Host tests install a recording
/// mock; the default stub models the real callee's known prefix (see
/// the module header) and can be swapped for the ported
/// `current_task_ctx_block` once cross-module wiring is wanted.
pub static mut CURRENT_TASK_CTX_BLOCK: unsafe extern "C" fn() -> *mut u8 =
    current_task_ctx_block_stub;

/// task_ctx_field_0x30 — original: `FUN_0827233c` @ 0x0827233c
/// (16 bytes).
///
/// Returns the word at +0x30 of the current task's context block. The
/// callee's result is NOT NULL-checked, exactly like the original (see
/// the module header): calling this with no current task dereferences
/// 0x30, reproducing the original's data abort.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_ctx_field_0x30() -> u32 {
    // Volatile slot read — the inner_state.rs rationale: the slot is
    // meant to be swapped at runtime, and a build in which nothing
    // swaps it must not constant-fold the default in.
    let ctx_block =
        core::ptr::read_volatile(core::ptr::addr_of!(CURRENT_TASK_CTX_BLOCK))();
    (ctx_block.add(FIELD) as *const u32).read()
}

/// task_ctx_set_field_0x30 — original: `FUN_0827234c` @ 0x0827234c
/// (20 bytes; 2 `bl` call sites).
///
/// The setter sibling of [`task_ctx_field_0x30`]:
///
/// ```text
/// push {r4, lr}
/// mov  r4, r0            @ keep the value across the call
/// bl   0x080cb828        @ ctx = current_task_ctx_block()
/// str  r4, [r0, #0x30]   @ ctx->+0x30 = value
/// pop  {r4, pc}
/// ```
///
/// Writes `value` to the word at +0x30 of the current task's context
/// block. Like the getter, the callee's result is NOT NULL-checked:
/// with no current task the original stores to 0x30 and takes a data
/// abort; the port keeps the unchecked store so the same fault is
/// reproduced rather than masked. Shares the [`CURRENT_TASK_CTX_BLOCK`]
/// dispatch slot with the getter (see the module header).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_ctx_set_field_0x30(value: u32) {
    let ctx_block =
        core::ptr::read_volatile(core::ptr::addr_of!(CURRENT_TASK_CTX_BLOCK))();
    (ctx_block.add(FIELD) as *mut u32).write(value);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    const CTX_LEN: usize = FIELD + 4;
    const SENTINEL: u8 = 0xa5;

    /// Serializes the tests that swap `CURRENT_TASK_CTX_BLOCK` (the
    /// inner_state.rs `SLOT_TEST_LOCK` precedent).
    static SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());

    static mut MOCK_CALLS: u32 = 0;
    static mut MOCK_CTX: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_ctx_block() -> *mut u8 {
        MOCK_CALLS += 1;
        MOCK_CTX
    }

    /// Restores the default stub on drop, even when a test panics.
    struct SlotGuard;
    impl Drop for SlotGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK)
                    .write_volatile(current_task_ctx_block_stub)
            };
        }
    }

    struct Fixture {
        ctx: [u8; CTX_LEN],
    }

    impl Fixture {
        fn new() -> Self {
            Fixture { ctx: [SENTINEL; CTX_LEN] }
        }
        fn with_field(mut self, value: u32) -> Self {
            self.ctx[FIELD..FIELD + 4].copy_from_slice(&value.to_le_bytes());
            self
        }
        fn install(&mut self) {
            unsafe {
                MOCK_CALLS = 0;
                MOCK_CTX = self.ctx.as_mut_ptr();
                core::ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK)
                    .write_volatile(recording_ctx_block);
            }
        }
        fn field(&self) -> u32 {
            u32::from_le_bytes(self.ctx[FIELD..FIELD + 4].try_into().unwrap())
        }
    }

    #[test]
    fn returns_the_field_word_and_calls_the_getter_once() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new().with_field(0xdead_beef);
        fixture.install();

        let value = unsafe { task_ctx_field_0x30() };

        assert_eq!(value, 0xdead_beef);
        assert_eq!(fixture.field(), 0xdead_beef);
        unsafe {
            assert_eq!(MOCK_CALLS, 1, "exactly one getter call");
        }
    }

    #[test]
    fn round_trips_edge_values() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        fixture.install();
        for value in [0u32, 1, 0x8000_0000, u32::MAX] {
            fixture.ctx[FIELD..FIELD + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(unsafe { task_ctx_field_0x30() }, value);
        }
        unsafe {
            assert_eq!(MOCK_CALLS, 4);
        }
    }

    #[test]
    fn reads_only_the_field_word() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new().with_field(0x2a);
        fixture.install();
        let before = fixture.ctx;

        unsafe { task_ctx_field_0x30() };

        assert_eq!(fixture.ctx, before, "the accessor is read-only");
    }

    #[test]
    fn default_stub_returns_null_when_the_kernel_is_not_started() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        // KERNEL_STARTED is born 0 and nothing in this test binary has
        // brought the kernel up, so kernel_running() reports no task —
        // the stub must take the callee's NULL path without dereferencing
        // the node.
        assert_eq!(unsafe { crate::kernel::sync_mutex::kernel_running() }, 0);
        assert!(unsafe { current_task_ctx_block_stub() }.is_null());
    }

    #[test]
    fn setter_writes_the_field_word_and_calls_the_getter_once() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        fixture.install();

        unsafe { task_ctx_set_field_0x30(0xdead_beef) };

        assert_eq!(fixture.field(), 0xdead_beef);
        unsafe {
            assert_eq!(MOCK_CALLS, 1, "exactly one getter call");
        }
    }

    #[test]
    fn setter_round_trips_edge_values_through_the_getter() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        fixture.install();
        for value in [0u32, 1, 0x8000_0000, u32::MAX] {
            unsafe { task_ctx_set_field_0x30(value) };
            assert_eq!(unsafe { task_ctx_field_0x30() }, value);
        }
        unsafe {
            assert_eq!(MOCK_CALLS, 8);
        }
    }

    #[test]
    fn setter_writes_only_the_field_word() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new().with_field(0x2a);
        fixture.install();
        let mut expected = fixture.ctx;
        expected[FIELD..FIELD + 4].copy_from_slice(&0xc0ff_eeu32.to_le_bytes());

        unsafe { task_ctx_set_field_0x30(0xc0ff_ee) };

        assert_eq!(fixture.ctx, expected, "the setter touches only +0x30");
    }
}

//! Task message-post shim — the synchronous (wait-for-reply) flavor of
//! the tagged task-message post helper.
//!
//! - `task_message_post_sync` — original: `FUN_0812bf70` @ 0x0812bf70
//!   (20 bytes; 2 `bl` call sites: 0x08111050 in `FUN_08110fdc` and
//!   0x08125228 in `FUN_081251cc`). Pure argument plumbing in front of
//!   the message-post helper @ 0x0812c088: it forwards (reply_queue,
//!   target_queue, message, flags) with the wait flag forced to 1, and
//!   returns the helper's result verbatim. Its mirror image @
//!   0x0812c628 (`FUN_0812c628`) is the identical 20-byte body with
//!   `mov r3, #0x0` — the fire-and-forget flavor.
//!
//! The helper @ 0x0812c088 (180 bytes, not yet ported) allocates a
//! message cell from the global pool (locked alloc @ 0x0812bf9c), copies
//! the 3-word tagged message into it, and posts it through
//! 0x080944b0 when the wait flag is nonzero (else 0x080f117c). Both
//! post backends bottom out in the queue send @ 0x0809eb58, whose
//! fifth argument is the wait-for-reply flag: 0x080944b0 passes 1
//! (the sender blocks the current task until the reply, per the
//! param_5 != 0 path there) and 0x080f117c passes 0. So the r3 this
//! shim forces to 1 selects the synchronous send — hence the name.
//!
//! Both call sites build the same 3-word stack message
//! {FourCC tag, arg, arg} and pass queue handles read out of task
//! context blocks (+0x1c, cf. `current_task_ctx_block` @ 0x080cb828 in
//! kernel/task.rs): r0 is the posting task's own (reply) queue, r1 the
//! target's. The exact semantics of the fourth argument (forwarded
//! verbatim as the helper's stack argument, and from there to the
//! queue send's cell-blocking flag) are not yet identified; the name
//! `flags` follows the data flow, nothing more (the
//! `timer_schedule_shim` precedent).
//!
//! Deviations:
//! - The helper @ 0x0812c088 is not yet ported, so the call dispatches
//!   indirectly through the `TASK_MESSAGE_OPS` fn-pointer table (the
//!   `TimerOps` pattern in drivers/timer.rs) instead of an undefined
//!   `extern "C"` symbol that would break the freestanding ARM link.
//!   The default stub returns 0 (post failed), the harmless choice —
//!   on real hardware the table must be installed before this shim is
//!   hooked. The slot is read with a volatile field read, the
//!   `timer_schedule_shim` precedent.
//! - The original spills its incoming r3 to the stack slot that becomes
//!   the helper's fifth (stack) argument (`stmdb sp!,{r3,lr};
//!   str r3,[sp,#0x0]`) — argument plumbing, not a saved register; the
//!   port expresses the same thing as a five-argument `extern "C"`
//!   call, which lowers to the same stack-arg store on ARM.
//! - Ghidra's scouted signature is `void FUN_0812bf70(void)`: it
//!   recovers neither the four register arguments nor the result. Both
//!   call sites consume the return value (`iVar2 = FUN_0812bf70(...);
//!   if (iVar2 != 0) return iVar2;`), so the signature is corrected to
//!   four arguments returning `u32` — the helper's 1-on-success /
//!   0-on-failure result.

/// Indirect dispatch table for the not-yet-ported message-post helper
/// (see the module header for the design and the default-stub
/// behavior).
#[derive(Clone, Copy)]
pub struct TaskMessageOps {
    /// Message-post helper @ 0x0812c088(reply_queue, target_queue,
    /// message, wait, flags) -> u32: allocates a message cell from the
    /// global pool, copies the 3-word tagged `message` into it, and
    /// posts it to `target_queue` — synchronously (blocking the sender
    /// for the reply) when `wait` is nonzero. Returns 1 on a
    /// successful post, 0 on failure. `task_message_post_sync` calls
    /// it with `wait` forced to 1.
    pub post_message: unsafe extern "C" fn(
        reply_queue: usize,
        target_queue: usize,
        message: *const u32,
        wait: u32,
        flags: u32,
    ) -> u32,
}

// Default stub: without the post layer a send has no meaning, and 0
// (post failed) is the harmless result — both call sites treat nonzero
// as an error code to propagate, and 0 falls through to the success
// path with nothing posted. On real hardware TASK_MESSAGE_OPS must be
// installed before this shim is hooked.
unsafe extern "C" fn missing_post_message(
    _reply_queue: usize,
    _target_queue: usize,
    _message: *const u32,
    _wait: u32,
    _flags: u32,
) -> u32 {
    0
}

/// The wired default: the not-yet-ported helper is the documented stub
/// above.
const DEFAULT_TASK_MESSAGE_OPS: TaskMessageOps = TaskMessageOps {
    post_message: missing_post_message,
};

/// The active task-message dispatch table. Defaults to
/// `DEFAULT_TASK_MESSAGE_OPS`; replaced by host tests (mocks) and
/// eventually by the ported post helper. Written once at init on
/// target; tests serialize access.
pub static mut TASK_MESSAGE_OPS: TaskMessageOps = DEFAULT_TASK_MESSAGE_OPS;

/// task_message_post_sync — original: `FUN_0812bf70` @ 0x0812bf70 (20
/// bytes).
///
/// Posts the 3-word tagged `message` to `target_queue` through the
/// message-post helper @ 0x0812c088 with the wait flag forced to 1 —
/// the synchronous flavor that blocks the sending task until the reply
/// (its mirror @ 0x0812c628 forces 0, the fire-and-forget flavor).
/// `reply_queue` is the posting task's own queue handle and `flags`
/// rides through verbatim as the helper's stack argument; both follow
/// the data flow only — see the module header. Returns the helper's
/// result: 1 on a successful post, 0 on failure. The helper is not yet
/// ported, so the call dispatches through `TASK_MESSAGE_OPS` (the
/// `TimerOps` pattern); the Ghidra `void (void)` signature is
/// corrected to four arguments returning `u32` from the call sites.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_message_post_sync(
    reply_queue: usize,
    target_queue: usize,
    message: *const u32,
    flags: u32,
) -> u32 {
    // Reads the fn-pointer field directly rather than the whole table:
    // the `timer_schedule_shim` precedent (a whole-table volatile read
    // breaks LLVM's ARM sibling-call lowering). The volatile load keeps
    // LLVM from constant-folding the default stub into a direct call.
    let post_message = core::ptr::addr_of!(TASK_MESSAGE_OPS.post_message).read_volatile();
    post_message(reply_queue, target_queue, message, 1, flags)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::vec::Vec;

    /// Serializes tests that swap the global ops table / mock state.
    static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    static CALLS: StdMutex<Vec<(usize, usize, usize, u32, u32)>> = StdMutex::new(Vec::new());

    /// Mock post helper: records the full argument tuple and returns
    /// the scripted result.
    static mut MOCK_RESULT: u32 = 0;

    unsafe extern "C" fn mock_post_message(
        reply_queue: usize,
        target_queue: usize,
        message: *const u32,
        wait: u32,
        flags: u32,
    ) -> u32 {
        CALLS.lock().unwrap().push((
            reply_queue,
            target_queue,
            message as usize,
            wait,
            flags,
        ));
        core::ptr::addr_of!(MOCK_RESULT).read_volatile()
    }

    /// Installs the mock, runs the shim once with the given arguments,
    /// and returns (shim result, recorded call tuple).
    fn run_case(
        result: u32,
        reply_queue: usize,
        target_queue: usize,
        message: *const u32,
        flags: u32,
    ) -> (u32, (usize, usize, usize, u32, u32)) {
        let _guard = OPS_LOCK.lock().unwrap();
        CALLS.lock().unwrap().clear();
        unsafe {
            core::ptr::addr_of_mut!(MOCK_RESULT).write_volatile(result);
            core::ptr::addr_of_mut!(TASK_MESSAGE_OPS).write_volatile(TaskMessageOps {
                post_message: mock_post_message,
            });
        }
        let ret = unsafe { task_message_post_sync(reply_queue, target_queue, message, flags) };
        let calls = CALLS.lock().unwrap().clone();
        unsafe {
            core::ptr::addr_of_mut!(TASK_MESSAGE_OPS).write_volatile(DEFAULT_TASK_MESSAGE_OPS);
        }
        assert_eq!(calls.len(), 1, "exactly one post call expected");
        (ret, calls[0])
    }

    #[test]
    fn forces_wait_flag_and_forwards_arguments() {
        let message: [u32; 3] = [0xdead_beef, 0x1111_2222, 0x3333_4444];
        let (ret, call) = run_case(1, 0x089c_0010, 0x089c_0020, message.as_ptr(), 0x55);
        assert_eq!(ret, 1);
        assert_eq!(
            call,
            (0x089c_0010, 0x089c_0020, message.as_ptr() as usize, 1, 0x55)
        );
    }

    #[test]
    fn result_propagates_verbatim() {
        // 0 (post failed) and nonzero values other than 1 must pass
        // through untouched — the callers propagate any nonzero value.
        let message: [u32; 3] = [0x4d53_4721, 7, 8];
        let (ret, _) = run_case(0, 1, 2, message.as_ptr(), 0);
        assert_eq!(ret, 0);
        let (ret, _) = run_case(0x8000_0007, 1, 2, message.as_ptr(), 0);
        assert_eq!(ret, 0x8000_0007);
    }

    #[test]
    fn wait_flag_is_one_even_when_flags_are_zero() {
        // The original's `mov r3, #0x1` is unconditional: the wait flag
        // is forced to 1 regardless of every other argument.
        let (ret, call) = run_case(0, 0, 0, core::ptr::null(), 0);
        assert_eq!(ret, 0);
        assert_eq!(call.3, 1);
        assert_eq!(call.0, 0);
        assert_eq!(call.1, 0);
        assert_eq!(call.2, 0);
        assert_eq!(call.4, 0);
    }

    #[test]
    fn default_stub_reports_failure_and_posts_nothing() {
        let _guard = OPS_LOCK.lock().unwrap();
        unsafe {
            core::ptr::addr_of_mut!(TASK_MESSAGE_OPS).write_volatile(DEFAULT_TASK_MESSAGE_OPS);
        }
        let message: [u32; 3] = [1, 2, 3];
        let ret = unsafe { task_message_post_sync(10, 20, message.as_ptr(), 30) };
        assert_eq!(ret, 0);
    }
}

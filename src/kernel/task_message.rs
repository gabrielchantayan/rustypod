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

use crate::kernel::condvar::{list_push_back, ListHead, ListNode};
use crate::kernel::csem::{csem_post_deferred, CountingSem};
use crate::kernel::kobj::{mailbox_slot_post, Mailbox};
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// Original: task-message pool mutex @ 0x089cb284. It brackets every
/// append to [`TASK_MESSAGE_FREE_LIST`].
pub static mut TASK_MESSAGE_POOL_MUTEX: Mutex = Mutex {
    sem_cell: core::ptr::null_mut(),
    unused: 0,
};

/// Original: task-message pool free-list anchor @ 0x089cb28c.
pub static mut TASK_MESSAGE_FREE_LIST: ListHead = ListHead {
    head: core::ptr::null_mut(),
    tail: core::ptr::null_mut(),
};

/// task_message_pool_release — original: `FUN_0812c1b4` @ 0x0812c1b4
/// (**48 bytes** true extent: 40 bytes of code plus the 8-byte literal pool
/// at 0x0812c1dc..0x0812c1e4; the next function begins at 0x0812c1e4).
///
/// **5 direct `bl` call sites, all unconditional; 0 predicated `bl` call
/// sites**, verified by decoding every ARM `B`/`BL` word in `osos.dec`
/// (0x08110e38, 0x0812c114, 0x0812c28c, 0x0812c5c0, 0x0812c600).
/// The body locks the task-message pool mutex @ 0x089cb284, appends `cell`
/// to its free list @ 0x089cb28c through `list_push_back` @ 0x080f1158,
/// then tail-branches to `mutex_unlock` @ 0x0807f6a0. Deliberate deviation:
/// the stock tail branch is expressed as a normal Rust return after unlock;
/// the mutex is copied through a volatile load so LLVM cannot fold its
/// null-initialized static and remove the lock pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_message_pool_release(cell: *mut ListNode) {
    let mut mutex = core::ptr::addr_of_mut!(TASK_MESSAGE_POOL_MUTEX).read_volatile();
    mutex_lock(&mut mutex);
    list_push_back(core::ptr::addr_of_mut!(TASK_MESSAGE_FREE_LIST), cell);
    mutex_unlock(&mut mutex);
}

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
pub(crate) const DEFAULT_TASK_MESSAGE_OPS: TaskMessageOps = TaskMessageOps {
    post_message: missing_post_message,
};

/// The active task-message dispatch table. Defaults to
/// `DEFAULT_TASK_MESSAGE_OPS`; replaced by host tests (mocks) and
/// eventually by the ported post helper. Written once at init on
/// target; tests serialize access.
pub static mut TASK_MESSAGE_OPS: TaskMessageOps = DEFAULT_TASK_MESSAGE_OPS;

/// Raw receive operation at `FUN_0807a2e8` @ 0x0807a2e8. Its identity is
/// not yet established beyond the observed queue/cell handoff, so this
/// seam deliberately names only that data flow.
#[derive(Clone, Copy)]
pub struct TaskMessageReceiveOps {
    /// Receives a cell from `queue`, writes its address to `result[1]`, and
    /// receives the caller's auxiliary pointer in both `result[0]` and r2.
    pub receive_cell: unsafe extern "C" fn(queue: usize, result: *mut u32, auxiliary: *mut u8) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_receive_cell(
    queue: usize,
    result: *mut u32,
    auxiliary: *mut u8,
) -> u32 {
    let receive: unsafe extern "C" fn(usize, *mut u32, *mut u8) -> u32 =
        unsafe { core::mem::transmute(0x0807_a2e8usize) };
    unsafe { receive(queue, result, auxiliary) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_receive_cell(
    _queue: usize,
    _result: *mut u32,
    _auxiliary: *mut u8,
) -> u32 {
    panic!("task_message_receive requires queue helper 0x0807a2e8")
}

const DEFAULT_TASK_MESSAGE_RECEIVE_OPS: TaskMessageReceiveOps = TaskMessageReceiveOps {
    receive_cell: {
        #[cfg(target_os = "none")]
        { firmware_receive_cell }
        #[cfg(not(target_os = "none"))]
        { missing_receive_cell }
    },
};

/// Active seam for the unported queue receive helper.
pub static mut TASK_MESSAGE_RECEIVE_OPS: TaskMessageReceiveOps = DEFAULT_TASK_MESSAGE_RECEIVE_OPS;

/// The received message's first word, literal `b"emit"` from 0x0812c620.
pub const TASK_MESSAGE_EMIT_TAG: u32 = 0x7469_6d65;
/// The marker written to the emitted message's word at `+0x20`, literal
/// `b"pots"` from 0x0812c624.
pub const TASK_MESSAGE_EMIT_POST_MARKER: u32 = 0x7374_6f70;
const TASK_MESSAGE_CELL_PAYLOAD_WORDS: usize = 7;

/// task_message_receive — original: `FUN_0812c5dc` @ **0x0812c5dc**
/// (**68 bytes** of code, 0x0812c5dc..0x0812c620; the two literal words at
/// 0x0812c620 and 0x0812c624 precede the next real function at 0x0812c628).
///
/// **4 direct, unconditional `bl` callers; 0 predicated `bl` callers**,
/// verified by decoding all ARM branch-with-link words in `osos.dec`
/// (0x0812bfec, 0x0812c2f0, 0x08148d04, 0x082921c4). The body has three
/// unconditional `bl` instructions and no predicated calls.
///
/// Receives a task-message cell through the queue helper @ 0x0807a2e8, copies
/// its seven payload words (cell `+0x04`) to `message`, returns the cell to
/// the global task-message pool, then stamps `b"pots"` at `message[3]+0x20`
/// when the copied tag is `b"emit"`.
///
/// Deliberate deviation: the queue helper remains an explicitly named
/// data-flow seam because its callee identity is not established. The target
/// default calls its retailOS address; the host default panics until a test
/// installs [`TASK_MESSAGE_RECEIVE_OPS`]. The target's two-word stack result
/// is represented as `[u32; 2]`, preserving its four-byte fields on hosts.
///
/// # Safety
///
/// `message` must point to seven writable target words. The installed receive
/// helper must place a valid pool cell address in `result[1]`; for an `emit`
/// message, `message[3]` must be a valid writable target address through
/// `+0x20`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_message_receive(
    queue: usize,
    message: *mut u32,
    auxiliary: *mut u8,
) {
    let mut result = [auxiliary as usize as u32, 0];
    let receive_cell =
        unsafe { core::ptr::addr_of!(TASK_MESSAGE_RECEIVE_OPS.receive_cell).read_volatile() };
    unsafe { receive_cell(queue, result.as_mut_ptr(), auxiliary) };

    let cell = result[1] as usize as *mut u32;
    for word in 0..TASK_MESSAGE_CELL_PAYLOAD_WORDS {
        unsafe { message.add(word).write_volatile(cell.add(word + 1).read_volatile()) };
    }
    unsafe { task_message_pool_release(cell.cast()) };

    if unsafe { message.read_volatile() } == TASK_MESSAGE_EMIT_TAG {
        let marker = unsafe { message.add(3).read_volatile() } as usize as *mut u32;
        unsafe { marker.add(8).write_volatile(TASK_MESSAGE_EMIT_POST_MARKER) };
    }
}

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
///
/// `#[inline(never)]`: the shim is a distinct `bl` target in the
/// original, and both its call sites are `bl`s. Without it LLVM folds
/// the body into `queued_message_post` (0x08110fdc) and merges that
/// function's two post branches into one call with a computed wait
/// flag — behaviorally identical, structurally one `bl` short.
#[inline(never)]
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

/// Target word containing the task-message transport pointer.
const TASK_MESSAGE_TRANSPORT_SLOT: *mut *mut u32 = 0x089c_b280 as *mut *mut u32;

#[cfg(not(target_os = "none"))]
static mut MOCK_TASK_MESSAGE_TRANSPORT: *mut u32 = core::ptr::null_mut();

#[inline(always)]
unsafe fn task_message_transport() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        TASK_MESSAGE_TRANSPORT_SLOT.read_volatile()
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of!(MOCK_TASK_MESSAGE_TRANSPORT).read_volatile()
    }
}

/// Writes `len` bytes to the retailOS ring described by `ring`.
///
/// The six target words are `{unused, data, start, read, write, mask}`.
/// The storage pointer is deliberately a target-width word rather than a
/// host pointer: every consumer of this transport has the firmware layout.
unsafe fn task_message_ring_write(ring: *mut u32, mut source: *const u8, len: u32) -> u32 {
    let mask = ring.add(5).read_volatile();
    let start = ring.add(2).read_volatile();
    let read = ring.add(3).read_volatile();
    let mut write = ring.add(4).read_volatile();
    if len > mask.wrapping_sub(write.wrapping_sub(read).wrapping_add(start) & mask) {
        return 0;
    }
    let data = ring.add(1).read_volatile() as usize as *mut u8;
    for _ in 0..len {
        data.add(write as usize).write_volatile(source.read_volatile());
        write = write.wrapping_add(1) & mask;
        source = source.add(1);
    }
    ring.add(4).write_volatile(write);
    1
}

#[cfg(target_os = "none")]
unsafe fn task_message_transport_lock(slot: *mut u32) {
    mutex_lock(slot.cast::<Mutex>());
}

#[cfg(not(target_os = "none"))]
unsafe fn task_message_transport_lock(_slot: *mut u32) {}

#[cfg(target_os = "none")]
unsafe fn task_message_transport_unlock(slot: *mut u32) {
    mutex_unlock(slot.cast::<Mutex>());
}

#[cfg(not(target_os = "none"))]
unsafe fn task_message_transport_unlock(_slot: *mut u32) {}

/// task_message_transport_enqueue — original: `FUN_0812c444` @ 0x0812c444
/// (**60 bytes**, 0x0812c444..0x0812c480: 56 code bytes plus the literal
/// transport-global word at 0x0812c468).
///
/// **4 direct `bl` callers: 2 unconditional and 2 `blne`; no other
/// predicated `bl` forms**, verified by decoding every A32 B/BL word in
/// `osos.dec` (0x08061910, 0x0819c974, 0x0819c99c, 0x0819ccc0). The
/// `deferred` flag selects either the mutex-protected ring at transport+12
/// followed by `mailbox_slot_post`, or the unprotected ring at transport+36
/// followed by `csem_post_deferred`; both write exactly 28 bytes and signal
/// only after a successful write. Deliberate deviations: the stock body
/// tail-branches to internal entries 0x08103a80/0x08103ad0; Rust expresses
/// their verified bodies directly, preserving their target-word layout. Host
/// mutex calls are no-ops because the firmware's 4-byte semaphore slot cannot
/// be cast to the host's 8-byte-pointer `Mutex`; target builds call the
/// ported mutex wrappers directly.
///
/// # Safety
///
/// `message` must point to 28 readable bytes. The transport slot and its
/// ring storage must be valid retailOS target-width objects.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_message_transport_enqueue(message: *const u8, deferred: u32) -> u32 {
    let transport = task_message_transport();
    if deferred == 0 {
        task_message_transport_lock(transport.add(1));
        let result = task_message_ring_write(transport.add(3), message, 28);
        task_message_transport_unlock(transport.add(1));
        if result != 0 {
            mailbox_slot_post(transport.cast::<*mut Mailbox>());
        }
        result
    } else {
        let result = task_message_ring_write(transport.add(9), message, 28);
        if result != 0 {
            csem_post_deferred(transport.read_volatile() as usize as *mut CountingSem);
        }
        result
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex as StdMutex;
    use std::vec::Vec;


    /// Serializes every test that swaps [`TASK_MESSAGE_OPS`] — including
    /// `app::queued_message`'s poster tests, which drive the same slot.
    pub(crate) static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    static CALLS: StdMutex<Vec<(usize, usize, usize, u32, u32)>> = StdMutex::new(Vec::new());

    /// Mock post helper: records the full argument tuple and returns
    /// the scripted result.
    static mut MOCK_RESULT: u32 = 0;
    static RECEIVE_CALL: StdMutex<Option<(usize, u32, usize)>> = StdMutex::new(None);
    static mut MOCK_RECEIVE_CELL: u32 = 0;

    static TRANSPORT_LOCK: StdMutex<()> = StdMutex::new(());

    unsafe extern "C" fn mock_receive_cell(
        queue: usize,
        result: *mut u32,
        auxiliary: *mut u8,
    ) -> u32 {
        let first = unsafe { result.read_volatile() };
        RECEIVE_CALL.lock().replace((queue, first, auxiliary as usize));
        unsafe { result.add(1).write_volatile(core::ptr::addr_of!(MOCK_RECEIVE_CELL).read_volatile()) };
        0
    }


    unsafe extern "C" fn mock_post_message(
        reply_queue: usize,
        target_queue: usize,
        message: *const u32,
        wait: u32,
        flags: u32,
    ) -> u32 {
        CALLS.lock().push((
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
        let _guard = OPS_LOCK.lock();
        CALLS.lock().clear();
        unsafe {
            core::ptr::addr_of_mut!(MOCK_RESULT).write_volatile(result);
            core::ptr::addr_of_mut!(TASK_MESSAGE_OPS).write_volatile(TaskMessageOps {
                post_message: mock_post_message,
            });
        }
        let ret = unsafe { task_message_post_sync(reply_queue, target_queue, message, flags) };
        let calls = CALLS.lock().clone();
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
        let _guard = OPS_LOCK.lock();
        unsafe {
            core::ptr::addr_of_mut!(TASK_MESSAGE_OPS).write_volatile(DEFAULT_TASK_MESSAGE_OPS);
        }
        let message: [u32; 3] = [1, 2, 3];
        let ret = unsafe { task_message_post_sync(10, 20, message.as_ptr(), 30) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn pool_release_appends_cells_and_clears_each_link() {
        let _guard = OPS_LOCK.lock();
        let mut first = ListNode {
            next: core::ptr::null_mut(),
        };
        let mut second = ListNode {
            next: &mut first,
        };

        unsafe {
            core::ptr::addr_of_mut!(TASK_MESSAGE_POOL_MUTEX).write_volatile(Mutex {
                sem_cell: core::ptr::null_mut(),
                unused: 0,
            });
            core::ptr::addr_of_mut!(TASK_MESSAGE_FREE_LIST).write_volatile(ListHead {
                head: core::ptr::null_mut(),
                tail: core::ptr::null_mut(),
            });

            task_message_pool_release(&mut first);
            assert!(core::ptr::eq(TASK_MESSAGE_FREE_LIST.head, &mut first));
            assert!(core::ptr::eq(TASK_MESSAGE_FREE_LIST.tail, &mut first));
            assert!(first.next.is_null());

            task_message_pool_release(&mut second);
            assert!(core::ptr::eq(TASK_MESSAGE_FREE_LIST.head, &mut first));
            assert!(core::ptr::eq(TASK_MESSAGE_FREE_LIST.tail, &mut second));
            assert!(core::ptr::eq(first.next, &mut second));
            assert!(second.next.is_null());
        }
    }
    #[test]
    fn receive_copies_cell_payload_releases_cell_and_stamps_emit_marker() {
        let _guard = OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::TASK_MESSAGE_RECEIVE, 0x100) else {
            return;
        };
        let cell = slab.cast::<u32>();
        let marker = unsafe { slab.add(0x40).cast::<u32>() };
        let auxiliary = unsafe { slab.add(0x80) };
        let mut message = [0u32; TASK_MESSAGE_CELL_PAYLOAD_WORDS];

        unsafe {
            cell.write_volatile(0);
            cell.add(1).write_volatile(TASK_MESSAGE_EMIT_TAG);
            cell.add(2).write_volatile(0x1111_2222);
            cell.add(3).write_volatile(0x3333_4444);
            cell.add(4).write_volatile(marker as usize as u32);
            cell.add(5).write_volatile(0x5555_5555);
            cell.add(6).write_volatile(0x6666_6666);
            cell.add(7).write_volatile(0x7777_7777);
            marker.add(8).write_volatile(0);
            core::ptr::addr_of_mut!(TASK_MESSAGE_POOL_MUTEX).write_volatile(Mutex {
                sem_cell: core::ptr::null_mut(),
                unused: 0,
            });
            core::ptr::addr_of_mut!(TASK_MESSAGE_FREE_LIST).write_volatile(ListHead {
                head: core::ptr::null_mut(),
                tail: core::ptr::null_mut(),
            });
            core::ptr::addr_of_mut!(MOCK_RECEIVE_CELL).write_volatile(cell as usize as u32);
            RECEIVE_CALL.lock().take();
            core::ptr::addr_of_mut!(TASK_MESSAGE_RECEIVE_OPS).write_volatile(TaskMessageReceiveOps {
                receive_cell: mock_receive_cell,
            });

            task_message_receive(0x089c_001c, message.as_mut_ptr(), auxiliary);

            core::ptr::addr_of_mut!(TASK_MESSAGE_RECEIVE_OPS)
                .write_volatile(DEFAULT_TASK_MESSAGE_RECEIVE_OPS);
        }

        assert_eq!(
            message,
            [
                TASK_MESSAGE_EMIT_TAG,
                0x1111_2222,
                0x3333_4444,
                marker as usize as u32,
                0x5555_5555,
                0x6666_6666,
                0x7777_7777,
            ]
        );
        assert_eq!(unsafe { marker.add(8).read_volatile() }, TASK_MESSAGE_EMIT_POST_MARKER);
        assert_eq!(*RECEIVE_CALL.lock(), Some((0x089c_001c, auxiliary as usize as u32, auxiliary as usize)));
        unsafe {
            assert_eq!(TASK_MESSAGE_FREE_LIST.head.cast::<u32>(), cell);
            assert_eq!(TASK_MESSAGE_FREE_LIST.tail.cast::<u32>(), cell);
        }
    }

    #[test]
    fn transport_enqueue_selects_ring_and_signals_only_after_success() {
        let _guard = TRANSPORT_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::TASK_MESSAGE_TRANSPORT_ENQUEUE, 0x200) else {
            return;
        };
        let transport = slab.cast::<u32>();
        let foreground_data = unsafe { slab.add(0x80) };
        let deferred_data = unsafe { slab.add(0xc0) };
        let semaphore = unsafe { slab.add(0x180).cast::<u32>() };
        let message: [u8; 28] = core::array::from_fn(|i| i as u8);

        unsafe {
            for word in 0..0x80 {
                transport.add(word).write_volatile(0);
            }
            semaphore.write_volatile(0);
            semaphore.add(1).write_volatile(0);
            transport.write_volatile(semaphore as usize as u32);
            transport.add(4).write_volatile(foreground_data as usize as u32);
            transport.add(8).write_volatile(0x1f);
            transport.add(10).write_volatile(deferred_data as usize as u32);
            transport.add(14).write_volatile(0x1f);
            core::ptr::addr_of_mut!(MOCK_TASK_MESSAGE_TRANSPORT).write_volatile(transport);

            assert_eq!(task_message_transport_enqueue(message.as_ptr(), 0), 1);
            assert_eq!(transport.add(7).read_volatile(), 28);
            assert_eq!(semaphore.read_volatile(), 1);
            for (index, byte) in message.iter().enumerate() {
                assert_eq!(foreground_data.add(index).read_volatile(), *byte);
            }

            semaphore.write_volatile(0);
            assert_eq!(task_message_transport_enqueue(message.as_ptr(), 1), 1);
            assert_eq!(transport.add(13).read_volatile(), 28);
            assert_eq!(semaphore.read_volatile(), 1);
            for (index, byte) in message.iter().enumerate() {
                assert_eq!(deferred_data.add(index).read_volatile(), *byte);
            }

            semaphore.write_volatile(0);
            transport.add(14).write_volatile(0);
            assert_eq!(task_message_transport_enqueue(message.as_ptr(), 1), 0);
            assert_eq!(semaphore.read_volatile(), 0);
            core::ptr::addr_of_mut!(MOCK_TASK_MESSAGE_TRANSPORT)
                .write_volatile(core::ptr::null_mut());
        }
    }

}

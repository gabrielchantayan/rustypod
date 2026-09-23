//! Task message posting and receiving.
//!
//! `task_message_post_sync` @ 0x0812bf70 and its fire-and-forget mirror @
//! 0x0812c628 force the `wait` argument of `task_message_post` below. Both
//! call sites construct a three-word `{FourCC tag, arg, arg}` message and
//! obtain their reply and target queue handles from task contexts.
//!
//! The lower queue operations remain deliberately narrow data-flow seams:
//! their retailOS identities have not been established. On target they call
//! their verified addresses; host tests install deterministic replacements.
//! This avoids claiming names or signatures unsupported by the raw code.

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

/// Operations below `task_message_post` whose identities are not yet known.
///
/// Each signature is established from the A32 call setup in
/// `FUN_0812c088`, rather than Ghidra's incomplete prototypes.
#[derive(Clone, Copy)]
pub struct TaskMessagePostOps {
    pub allocate_cell: unsafe extern "C" fn() -> *mut u32,
    pub queue_send: unsafe extern "C" fn(usize, usize, *mut u32, u32, u32, u32) -> u32,
    pub post_with_wait: unsafe extern "C" fn(usize, usize, *mut u32, u32) -> u32,
    pub allocation_failed: unsafe extern "C" fn(*mut u32, *mut *const u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_allocate_cell() -> *mut u32 {
    let allocate: unsafe extern "C" fn() -> *mut u32 = unsafe { core::mem::transmute(0x0812_bf9cusize) };
    unsafe { allocate() }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_queue_send(
    reply_queue: usize, target_queue: usize, cell: *mut u32, cell_blocking: u32, wait_for_reply: u32, flags: u32,
) -> u32 {
    let send: unsafe extern "C" fn(usize, usize, *mut u32, u32, u32, u32) -> u32 =
        unsafe { core::mem::transmute(0x0809_eb58usize) };
    unsafe { send(reply_queue, target_queue, cell, cell_blocking, wait_for_reply, flags) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_post_with_wait(reply_queue: usize, target_queue: usize, cell: *mut u32, flags: u32) -> u32 {
    let post: unsafe extern "C" fn(usize, usize, *mut u32, u32) -> u32 =
        unsafe { core::mem::transmute(0x0809_44b0usize) };
    unsafe { post(reply_queue, target_queue, cell, flags) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_allocation_failed(wait: *mut u32, message: *mut *const u32) {
    let failed: unsafe extern "C" fn(*mut u32, *mut *const u32) =
        unsafe { core::mem::transmute(0x080d_c8a4usize) };
    unsafe { failed(wait, message) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate_cell() -> *mut u32 {
    panic!("task_message_post requires pool helper 0x0812bf9c")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_queue_send(
    _reply_queue: usize, _target_queue: usize, _cell: *mut u32, _cell_blocking: u32, _wait_for_reply: u32, _flags: u32,
) -> u32 {
    panic!("task_message_post requires queue send helper 0x0809eb58")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_post(_reply_queue: usize, _target_queue: usize, _cell: *mut u32, _flags: u32) -> u32 {
    panic!("task_message_post requires queue post helper")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocation_failed(_wait: *mut u32, _message: *mut *const u32) {
    panic!("task_message_post requires allocation-failure helper 0x080dc8a4")
}

pub(crate) const DEFAULT_TASK_MESSAGE_POST_OPS: TaskMessagePostOps = TaskMessagePostOps {
    allocate_cell: {
        #[cfg(target_os = "none")]
        { firmware_allocate_cell }
        #[cfg(not(target_os = "none"))]
        { missing_allocate_cell }
    },
    queue_send: {
        #[cfg(target_os = "none")]
        { firmware_queue_send }
        #[cfg(not(target_os = "none"))]
        { missing_queue_send }
    },
    post_with_wait: {
        #[cfg(target_os = "none")]
        { firmware_post_with_wait }
        #[cfg(not(target_os = "none"))]
        { missing_post }
    },
    allocation_failed: {
        #[cfg(target_os = "none")]
        { firmware_allocation_failed }
        #[cfg(not(target_os = "none"))]
        { missing_allocation_failed }
    },
};

/// Active seams for the unported allocation and queue-post operations.
pub static mut TASK_MESSAGE_POST_OPS: TaskMessagePostOps = DEFAULT_TASK_MESSAGE_POST_OPS;
/// copy_seven_words — original: `FUN_0827210c` @ **0x0827210c**
/// (**48 bytes**, 0x0827210c..0x0827213b; the next function starts at
/// 0x0827213c).
///
/// **3 direct `bl` callers, all unconditional; 0 predicated `bl` callers**,
/// verified by decoding every A32 branch-with-link word in `osos.dec`
/// (0x0812c0b4, 0x0812c284, 0x0812c5f8).
///
/// Copies seven aligned 32-bit words from `src` to `dst`. It loads and stores
/// words 0, 1, and 2 individually, then loads all of words 3 through 6 before
/// storing that final group, preserving the source's observable overlap order.
///
/// Deliberate deviation: volatile accesses prevent LLVM from replacing the
/// fixed word sequence with a bulk-copy builtin. No NULL, bounds, alignment,
/// or overlap check is added; callers must provide seven readable source words
/// and seven writable destination words, exactly as the original requires.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn copy_seven_words(dst: *mut u32, src: *const u32) {
    unsafe {
        dst.write_volatile(src.read_volatile());
        dst.add(1).write_volatile(src.add(1).read_volatile());
        dst.add(2).write_volatile(src.add(2).read_volatile());

        let word3 = src.add(3).read_volatile();
        let word4 = src.add(4).read_volatile();
        let word5 = src.add(5).read_volatile();
        let word6 = src.add(6).read_volatile();
        dst.add(3).write_volatile(word3);
        dst.add(4).write_volatile(word4);
        dst.add(5).write_volatile(word5);
        dst.add(6).write_volatile(word6);
    }
}

/// post_without_wait — original: `FUN_080f117c` @ **0x080f117c**
/// (**40 bytes** exactly, 0x080f117c..0x080f11a4; the next real function
/// starts with `push {r0,r1,r4,r5,r6,lr}` at 0x080f11a4).
///
/// **4 direct `bl` callers: 3 unconditional and 1 `blne`** (0x0808f754,
/// 0x081214ec, 0x0812c100, 0x08295ad0), verified by decoding every A32
/// branch-with-link word in `osos.dec`. The body makes one unconditional
/// `bl` and no predicated calls.
///
/// Forwards the first four arguments and fifth stack argument to the queue
/// send helper @ 0x0809eb58, forcing its wait-for-reply argument to zero.
/// Deliberate deviation: the A32 stack argument shuffle is represented as a
/// six-argument Rust call; it preserves the callee's values, including its
/// return value, rather than reproducing the caller's stack layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn post_without_wait(
    reply_queue: usize, target_queue: usize, cell: *mut u32, cell_blocking: u32, flags: u32,
) -> u32 {
    let queue_send = unsafe { core::ptr::addr_of!(TASK_MESSAGE_POST_OPS).read_volatile().queue_send };
    unsafe { queue_send(reply_queue, target_queue, cell, cell_blocking, 0, flags) }
}

/// task_message_post — original: `FUN_0812c088` @ **0x0812c088**
/// (**188 bytes** true extent: 180 bytes of code followed by the two literal
/// words at 0x0812c13c and 0x0812c140; the next function starts at
/// 0x0812c144).
///
/// **4 direct `bl` callers: 3 unconditional and 1 `blne`** (0x0812bf7c,
/// 0x0812c194, 0x0812c238, 0x0812c634), verified by decoding every A32
/// branch-with-link word in `osos.dec`. The body makes five unconditional
/// calls and no predicated calls.
///
/// Allocates a message cell, copies seven source words to cell `+4`, then
/// posts it with or without a wait according to `wait`. A successful backend
/// post returns 0 and becomes 1 here; a failed post returns the cell to the
/// pool and becomes 0. On allocation failure, only tag `0x5765_656c` invokes
/// the observed allocation-failure helper with stack-local `{wait, message}`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_message_post(
    reply_queue: usize, target_queue: usize, message: *const u32, wait: u32, flags: u32,
) -> u32 {
    let cell = unsafe { (core::ptr::addr_of!(TASK_MESSAGE_POST_OPS).read_volatile().allocate_cell)() };
    if cell.is_null() {
        if unsafe { message.read() } == 0x5765_656c {
            let mut saved_wait = wait;
            let mut saved_message = message;
            unsafe { (core::ptr::addr_of!(TASK_MESSAGE_POST_OPS).read_volatile().allocation_failed)(&mut saved_wait, &mut saved_message) };
        }
        return 0;
    }
    unsafe { copy_seven_words(cell.add(1), message) };
    let ops = unsafe { core::ptr::addr_of!(TASK_MESSAGE_POST_OPS).read_volatile() };
    let result = unsafe {
        if wait == 0 { post_without_wait(reply_queue, target_queue, cell, flags, flags) }
        else { (ops.post_with_wait)(reply_queue, target_queue, cell, flags) }
    };
    if result == 0 { 1 } else { unsafe { task_message_pool_release(cell.cast::<ListNode>()); } 0 }
}

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

/// Queue-handler lookup boundaries used by [`task_message_dispatch`].
///
/// `FUN_081b5344` has not been named from raw evidence. Its call setup proves
/// only that it initializes a handler lookup; the already ported
/// `collection_find_previous_handler` is the subsequent lookup operation.
/// Callback and context outputs are `usize` so host fixtures do not truncate
/// their function pointers; they are 32-bit target words on ARM.
#[derive(Clone, Copy)]
pub struct TaskMessageDispatchOps {
    pub current_context: unsafe extern "C" fn() -> *mut u32,
    pub find_first_handler: unsafe extern "C" fn(*mut u8, u32, *mut usize, *mut usize, *mut i32) -> u32,
    pub find_previous_handler: unsafe extern "C" fn(*mut u8, u32, *mut usize, *mut usize, *mut i32) -> u32,
}

type TaskMessageHandler = unsafe extern "C" fn(*mut u32, usize) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_current_task_context() -> *mut u32 {
    unsafe { crate::kernel::task::current_task_ctx_block().cast() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_task_context() -> *mut u32 {
    panic!("task_message_dispatch requires current task context")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_find_first_handler(
    owner: *mut u8, key: u32, callback: *mut usize, context: *mut usize, cursor: *mut i32,
) -> u32 {
    let find: unsafe extern "C" fn(*mut u8, u32, *mut usize, *mut usize, *mut i32) -> u32 =
        unsafe { core::mem::transmute(0x081b_5344usize) };
    unsafe { find(owner, key, callback, context, cursor) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_find_previous_handler(
    owner: *mut u8, key: u32, callback: *mut usize, context: *mut usize, cursor: *mut i32,
) -> u32 {
    unsafe {
        crate::app::vtable_set::collection_find_previous_handler(
            owner, key, callback.cast(), context.cast(), cursor,
        )
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_find_handler(
    _owner: *mut u8, _key: u32, _callback: *mut usize, _context: *mut usize, _cursor: *mut i32,
) -> u32 {
    panic!("task_message_dispatch requires handler helper 0x081b5344")
}

const DEFAULT_TASK_MESSAGE_DISPATCH_OPS: TaskMessageDispatchOps = TaskMessageDispatchOps {
    current_context: {
        #[cfg(target_os = "none")]
        { firmware_current_task_context }
        #[cfg(not(target_os = "none"))]
        { missing_current_task_context }
    },
    find_first_handler: {
        #[cfg(target_os = "none")]
        { firmware_find_first_handler }
        #[cfg(not(target_os = "none"))]
        { missing_find_handler }
    },
    find_previous_handler: {
        #[cfg(target_os = "none")]
        { firmware_find_previous_handler }
        #[cfg(not(target_os = "none"))]
        { missing_find_handler }
    },
};

/// Active lookup boundaries for task-message handler dispatch.
pub static mut TASK_MESSAGE_DISPATCH_OPS: TaskMessageDispatchOps = DEFAULT_TASK_MESSAGE_DISPATCH_OPS;

/// The terminal task message, literal `b"tiuq"` at 0x0812c084.
const TASK_MESSAGE_QUIT_TAG: u32 = 0x7175_6974;

/// task_message_dispatch — original: `FUN_0812bfcc` @ **0x0812bfcc**
/// (**188 bytes** true extent: 184 bytes of instructions through 0x0812c084,
/// then the `b"tiuq"` literal; the next real function begins at 0x0812c088).
///
/// **3 direct `bl` callers, all unconditional; 0 predicated direct `bl`
/// callers** (0x0839d978, 0x0839daf8, 0x0839dde0). The body has three
/// unconditional direct `bl` instructions, one `blne`, and one indirect
/// `blx`, verified by decoding every instruction word in `osos.dec`.
///
/// Receives messages from the current task context's queue at +0x1c. For a
/// non-NULL handler collection at +0x20, it finds a matching handler for the
/// message tag, invokes candidates until one returns nonzero, then recycles
/// the receive auxiliary node when present. It stops only after processing
/// the `b"tiuq"` message.
///
/// Deliberate deviations: the unnamed first-lookup helper @ 0x081b5344 and
/// host-width callback pointers are explicit seams. Rust expresses the
/// indirect `blx` as a typed call and the conditional recycle as an ordinary
/// `if`; target queue, callback, and context words remain 32-bit.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_message_dispatch() {
    let context = unsafe { core::ptr::addr_of!(TASK_MESSAGE_DISPATCH_OPS.current_context).read_volatile()() };
    let queue = unsafe { context.add(7).read_volatile() as usize };
    loop {
        let mut message = [0u32; TASK_MESSAGE_CELL_PAYLOAD_WORDS];
        let mut auxiliary = core::ptr::null_mut::<u8>();
        unsafe { task_message_receive(queue, message.as_mut_ptr(), core::ptr::addr_of_mut!(auxiliary).cast()) };

        let handlers = unsafe { context.add(8).read_volatile() as usize as *mut u8 };
        if !handlers.is_null() {
            let ops = unsafe { core::ptr::addr_of!(TASK_MESSAGE_DISPATCH_OPS).read_volatile() };
            let mut callback = 0usize;
            let mut callback_context = 0usize;
            let mut cursor = 0i32;
            let mut found = unsafe {
                (ops.find_first_handler)(
                    handlers, message[0], &mut callback, &mut callback_context, &mut cursor,
                )
            };
            while found != 0 {
                let handler: TaskMessageHandler = unsafe { core::mem::transmute(callback) };
                if unsafe { handler(message.as_mut_ptr(), callback_context) } != 0 {
                    break;
                }
                found = unsafe {
                    (ops.find_previous_handler)(
                        handlers, message[0], &mut callback, &mut callback_context, &mut cursor,
                    )
                };
            }
        }

        if !auxiliary.is_null() {
            unsafe { crate::kernel::mqueue::mqueue_node_recycle(auxiliary.cast()) };
        }
        if message[0] == TASK_MESSAGE_QUIT_TAG {
            return;
        }
    }
}

/// task_message_post_sync — original: `FUN_0812bf70` @ 0x0812bf70 (20
/// bytes).
///
/// Posts the 3-word tagged `message` with `wait` forced to 1, returning
/// `task_message_post`'s 1-on-success / 0-on-failure result.
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
    unsafe { task_message_post(reply_queue, target_queue, message, 1, flags) }
}
/// task_message_post_async — original: `FUN_0812c628` @ **0x0812c628**
/// (**20 bytes**, 0x0812c628..0x0812c63c; the next real function begins at
/// 0x0812c63c).
/// **3 direct `bl` callers: 2 unconditional and 1 `blne`** (0x08111048,
/// 0x0812521c, 0x08148dac), verified by decoding every A32 branch-with-link
/// word in `osos.dec`. The body makes one unconditional call and no
/// predicated calls.
///
/// Posts the 3-word tagged `message` with `wait` forced to 0, forwarding the
/// other four arguments and returning `task_message_post`'s result.
///
/// Deliberate deviation: the A32 push/store sequence places `flags` in the
/// fifth stack argument before the helper call; Rust represents that ABI
/// plumbing as a five-argument call while preserving every forwarded value.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_message_post_async(
    reply_queue: usize,
    target_queue: usize,
    message: *const u32,
    flags: u32,
) -> u32 {
    unsafe { task_message_post(reply_queue, target_queue, message, 0, flags) }
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


    /// Serializes every test that swaps [`TASK_MESSAGE_POST_OPS`] — including
    /// `app::queued_message`'s posting tests.
    pub(crate) static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    static CALLS: StdMutex<Vec<(usize, usize, u32, u32)>> = StdMutex::new(Vec::new());
    static mut MOCK_RESULT: u32 = 0;
    #[repr(align(8))]
    struct MockCell([u32; 8]);
    static mut MOCK_CELL: MockCell = MockCell([0; 8]);
    static mut MOCK_ALLOCATE: *mut u32 = core::ptr::null_mut();
    static mut ALLOCATION_FAILURES: u32 = 0;
    static RECEIVE_CALL: StdMutex<Option<(usize, u32, usize)>> = StdMutex::new(None);
    static mut MOCK_RECEIVE_CELL: u32 = 0;
    static TRANSPORT_LOCK: StdMutex<()> = StdMutex::new(());

    unsafe extern "C" fn mock_allocate_cell() -> *mut u32 {
        core::ptr::addr_of!(MOCK_ALLOCATE).read_volatile()
    }
    unsafe extern "C" fn mock_queue_send(
        reply: usize, target: usize, _cell: *mut u32, _cell_blocking: u32, wait_for_reply: u32, flags: u32,
    ) -> u32 {
        CALLS.lock().push((reply, target, wait_for_reply, flags));
        core::ptr::addr_of!(MOCK_RESULT).read_volatile()
    }
    unsafe extern "C" fn mock_post_with_wait(reply: usize, target: usize, cell: *mut u32, flags: u32) -> u32 {
        CALLS.lock().push((reply, target, 1, flags));
        core::ptr::addr_of!(MOCK_RESULT).read_volatile()
    }
    unsafe extern "C" fn mock_allocation_failed(_wait: *mut u32, _message: *mut *const u32) {
        core::ptr::addr_of_mut!(ALLOCATION_FAILURES).write_volatile(
            core::ptr::addr_of!(ALLOCATION_FAILURES).read_volatile() + 1,
        );
    }

    unsafe extern "C" fn mock_receive_cell(
        queue: usize, result: *mut u32, auxiliary: *mut u8,
    ) -> u32 {
        let first = unsafe { result.read_volatile() };
        RECEIVE_CALL.lock().replace((queue, first, auxiliary as usize));
        unsafe { result.add(1).write_volatile(core::ptr::addr_of!(MOCK_RECEIVE_CELL).read_volatile()) };
        0
    }

    static DISPATCH_EVENTS: StdMutex<Vec<(u32, usize)>> = StdMutex::new(Vec::new());
    static mut DISPATCH_CONTEXT: *mut u32 = core::ptr::null_mut();
    static mut DISPATCH_RECEIVES: u32 = 0;
    static mut DISPATCH_NEXT: u32 = 0;

    unsafe extern "C" fn mock_dispatch_context() -> *mut u32 {
        unsafe { core::ptr::addr_of!(DISPATCH_CONTEXT).read_volatile() }
    }
    unsafe extern "C" fn mock_dispatch_receive(_: usize, result: *mut u32, _: *mut u8) -> u32 {
        let receive = unsafe { core::ptr::addr_of!(DISPATCH_RECEIVES).read_volatile() };
        unsafe { core::ptr::addr_of_mut!(DISPATCH_RECEIVES).write_volatile(receive + 1) };
        let cell = unsafe { core::ptr::addr_of!(MOCK_RECEIVE_CELL).read_volatile() as usize as *mut u32 };
        unsafe {
            cell.add(1).write_volatile(if receive == 0 { 0x1234_5678 } else { TASK_MESSAGE_QUIT_TAG });
            result.add(1).write_volatile(cell as usize as u32);
        }
        0
    }
    unsafe extern "C" fn mock_first_handler(_: *mut u8, _: u32, callback: *mut usize, context: *mut usize, _: *mut i32) -> u32 {
        unsafe { callback.write(mock_decline as usize); context.write(0x11); }
        1
    }
    unsafe extern "C" fn mock_next_handler(_: *mut u8, _: u32, callback: *mut usize, context: *mut usize, _: *mut i32) -> u32 {
        let next = unsafe { core::ptr::addr_of!(DISPATCH_NEXT).read_volatile() };
        unsafe { core::ptr::addr_of_mut!(DISPATCH_NEXT).write_volatile(next + 1) };
        if next == 0 {
            unsafe { callback.write(mock_accept as usize); context.write(0x22); }
            1
        } else { 0 }
    }
    unsafe extern "C" fn mock_decline(message: *mut u32, context: usize) -> u32 {
        DISPATCH_EVENTS.lock().push((unsafe { message.read_volatile() }, context)); 0
    }
    unsafe extern "C" fn mock_accept(message: *mut u32, context: usize) -> u32 {
        DISPATCH_EVENTS.lock().push((unsafe { message.read_volatile() }, context)); 1
    }

    #[test]
    fn copy_seven_words_preserves_all_words_and_boundary_guards() {
        let source = [0x0000_0000, 0xffff_ffff, 0x1234_5678, 0x89ab_cdef, 4, 5, 6];
        let mut destination = [0xa5a5_a5a5; 9];

        unsafe { copy_seven_words(destination.as_mut_ptr().add(1), source.as_ptr()) };

        assert_eq!(&destination[1..8], &source);
        assert_eq!(destination[0], 0xa5a5_a5a5);
        assert_eq!(destination[8], 0xa5a5_a5a5);
    }

    #[test]
    fn copy_seven_words_matches_instruction_order_when_overlapping() {
        let mut actual = [0u32, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut expected = actual;

        for index in 0..3 {
            expected[index + 1] = expected[index];
        }
        let tail = [expected[3], expected[4], expected[5], expected[6]];
        expected[4..8].copy_from_slice(&tail);

        unsafe { copy_seven_words(actual.as_mut_ptr().add(1), actual.as_ptr()) };

        assert_eq!(actual, expected);
    }

    #[test]
    fn posts_seven_words_and_inverts_backend_status() {
        let _guard = OPS_LOCK.lock();
        unsafe { core::ptr::addr_of_mut!(MOCK_RESULT).write_volatile(0) };
        CALLS.lock().clear();
        let message = [0x1234_5678, 1, 2, 3, 4, 5, 6];
        unsafe {
            core::ptr::addr_of_mut!(MOCK_ALLOCATE).write_volatile(core::ptr::addr_of_mut!(MOCK_CELL.0).cast::<u32>());
            core::ptr::addr_of_mut!(TASK_MESSAGE_POST_OPS).write_volatile(TaskMessagePostOps {
                allocate_cell: mock_allocate_cell, queue_send: mock_queue_send,
                post_with_wait: mock_post_with_wait, allocation_failed: mock_allocation_failed,
            });
        }
        assert_eq!(unsafe { task_message_post(10, 20, message.as_ptr(), 1, 0x55) }, 1);
        assert_eq!(unsafe { core::ptr::addr_of!(MOCK_CELL.0).cast::<u32>().add(1).read() }, message[0]);
        assert_eq!(unsafe { core::ptr::addr_of!(MOCK_CELL.0).cast::<u32>().add(7).read() }, message[6]);
        assert_eq!(CALLS.lock().as_slice(), &[(10, 20, 1, 0x55)]);
        unsafe { core::ptr::addr_of_mut!(TASK_MESSAGE_POST_OPS).write_volatile(DEFAULT_TASK_MESSAGE_POST_OPS) };
    }

    #[test]
    fn post_without_wait_forces_reply_wait_off_and_forwards_flags() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            CALLS.lock().clear();
            core::ptr::addr_of_mut!(MOCK_RESULT).write_volatile(0x55);
            core::ptr::addr_of_mut!(TASK_MESSAGE_POST_OPS).write_volatile(TaskMessagePostOps {
                allocate_cell: mock_allocate_cell, queue_send: mock_queue_send,
                post_with_wait: mock_post_with_wait, allocation_failed: mock_allocation_failed,
            });
        }
        let cell = core::ptr::without_provenance_mut::<u32>(0x1234_5000);
        assert_eq!(unsafe { post_without_wait(10, 20, cell, 0x33, 0) }, 0x55);
        assert_eq!(unsafe { post_without_wait(11, 21, cell, 0x44, 0x66) }, 0x55);
        assert_eq!(CALLS.lock().as_slice(), &[(10, 20, 0, 0), (11, 21, 0, 0x66)]);
        unsafe { core::ptr::addr_of_mut!(MOCK_RESULT).write_volatile(0) };
        unsafe { core::ptr::addr_of_mut!(TASK_MESSAGE_POST_OPS).write_volatile(DEFAULT_TASK_MESSAGE_POST_OPS) };
    }

    #[test]
    fn async_post_forces_wait_off_and_forwards_all_other_arguments() {
        let _guard = OPS_LOCK.lock();
        let message = [0x1234_5678, 1, 2, 3, 4, 5, 6];
        unsafe {
            CALLS.lock().clear();
            core::ptr::addr_of_mut!(MOCK_RESULT).write_volatile(0);
            core::ptr::addr_of_mut!(MOCK_ALLOCATE).write_volatile(core::ptr::addr_of_mut!(MOCK_CELL.0).cast::<u32>());
            core::ptr::addr_of_mut!(TASK_MESSAGE_POST_OPS).write_volatile(TaskMessagePostOps {
                allocate_cell: mock_allocate_cell, queue_send: mock_queue_send,
                post_with_wait: mock_post_with_wait, allocation_failed: mock_allocation_failed,
            });
        }

        assert_eq!(unsafe { task_message_post_async(0x10, 0x20, message.as_ptr(), 0x55) }, 1);
        assert_eq!(CALLS.lock().as_slice(), &[(0x10, 0x20, 0, 0x55)]);

        unsafe { core::ptr::addr_of_mut!(TASK_MESSAGE_POST_OPS).write_volatile(DEFAULT_TASK_MESSAGE_POST_OPS) };
    }

    #[test]
    fn allocation_failure_notifies_only_the_weel_tag() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            core::ptr::addr_of_mut!(MOCK_ALLOCATE).write_volatile(core::ptr::null_mut());
            core::ptr::addr_of_mut!(ALLOCATION_FAILURES).write_volatile(0);
            core::ptr::addr_of_mut!(TASK_MESSAGE_POST_OPS).write_volatile(TaskMessagePostOps {
                allocate_cell: mock_allocate_cell, queue_send: mock_queue_send,
                post_with_wait: mock_post_with_wait, allocation_failed: mock_allocation_failed,
            });
        }
        assert_eq!(unsafe { task_message_post(0, 0, [0x5765_656c, 0, 0, 0, 0, 0, 0].as_ptr(), 0, 0) }, 0);
        assert_eq!(unsafe { core::ptr::addr_of!(ALLOCATION_FAILURES).read_volatile() }, 1);
        unsafe { core::ptr::addr_of_mut!(TASK_MESSAGE_POST_OPS).write_volatile(DEFAULT_TASK_MESSAGE_POST_OPS) };
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
    fn dispatches_candidates_until_handled_then_stops_after_terminal_message() {
        let _guard = OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::TASK_MESSAGE_RECEIVE, 0x100) else { return };
        let cell = slab.cast::<u32>();
        let mut context = [0u32; 9];
        unsafe {
            cell.write_volatile(0);
            for word in 2..8 { cell.add(word).write_volatile(0); }
            TASK_MESSAGE_POOL_MUTEX = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };
            TASK_MESSAGE_FREE_LIST = ListHead { head: core::ptr::null_mut(), tail: core::ptr::null_mut() };
            MOCK_RECEIVE_CELL = cell as usize as u32;
            DISPATCH_CONTEXT = context.as_mut_ptr();
            DISPATCH_RECEIVES = 0;
            DISPATCH_NEXT = 0;
            DISPATCH_EVENTS.lock().clear();
            context[7] = 0x89cb_0000;
            context[8] = 1;
            TASK_MESSAGE_RECEIVE_OPS = TaskMessageReceiveOps { receive_cell: mock_dispatch_receive };
            TASK_MESSAGE_DISPATCH_OPS = TaskMessageDispatchOps {
                current_context: mock_dispatch_context,
                find_first_handler: mock_first_handler,
                find_previous_handler: mock_next_handler,
            };
            task_message_dispatch();
            TASK_MESSAGE_RECEIVE_OPS = DEFAULT_TASK_MESSAGE_RECEIVE_OPS;
            TASK_MESSAGE_DISPATCH_OPS = DEFAULT_TASK_MESSAGE_DISPATCH_OPS;
        }
        assert_eq!(
            DISPATCH_EVENTS.lock().as_slice(),
            &[(0x1234_5678, 0x11), (0x1234_5678, 0x22), (TASK_MESSAGE_QUIT_TAG, 0x11)]
        );
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

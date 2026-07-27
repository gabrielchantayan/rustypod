//! RTXC task objects — the RAM-side create/start/destroy layer over the
//! mask-ROM kernel gateway, plus the task-notify helper the kernel-running
//! query pings.
//!
//! A task is a 0x44-byte RAM record plus a heap-allocated stack:
//!
//! ```text
//! +0x00  id       kernel object id (gateway service 0x17)
//! +0x04  entry    trampoline the caller passes (0x08074990 from the one
//! |               stock creator, FUN_0807a15c)
//! +0x08  context  caller's per-task record (the word 0x0805665c reads
//! |               back as the "current task id")
//! +0x0c  name     0x31-byte strncpy'd task name
//! +0x3d  NUL      forced terminator (one past the strncpy window)
//! +0x3e  pad
//! +0x40  stack    os_malloc(stack_size)
//! ```
//!
//! Originals:
//!
//! - `task_create` — `FUN_080563a0` @ 0x080563a0 (200 bytes; 1 call site,
//!   the spawn front-end `FUN_0807a15c` @ 0x0807a15c which maps its
//!   priority-flag argument to a level 0..8 and packs the caller record).
//!   Sequence: gateway id alloc (thunk 0x08037e28 -> ROM 0x22003b6c,
//!   service 0x17); `os_malloc(stack_size)`; `os_malloc(0x44)`;
//!   `memzero_aligned(rec, 0x44)` (thunk 0x08037db8 — the ROM copy of the
//!   ported memzero_aligned); fill the record; `strncpy(rec->name, name,
//!   0x31)` (ported 0x080310d4) + forced NUL; priority-level map
//!   `FUN_080e4348` (0->0x7e .. 8->8, default = identity); gateway task
//!   init (thunk 0x08037e30 -> ROM 0x22003c98: id, mapped priority,
//!   stack, stack_size, and the opaque literal 0x0809c5c8 as the 5th
//!   argument); gateway register (thunk 0x08037e38 -> ROM 0x22003d00,
//!   service 41: id, rec); name-table insert `FUN_0806331c` (0x50-entry
//!   {id, name} table @ *0x08063358, result discarded); then
//!   `task_start(...)` and return the record. Neither os_malloc result is
//!   NULL-checked (faithful).
//! - `task_start` — `FUN_080b4c44` @ 0x080b4c44 (8 bytes; 1 call site,
//!   task_create). `ldr r0, [sp, #4]; b 0x08037f78`: forwards its SIXTH
//!   argument (the id) to ROM 0x22003e00 — gateway service 0x15 with the
//!   id, per the osos mirror @ 0x08003e00 — ignoring all others.
//! - `task_destroy` — `FUN_080b4c4c` @ 0x080b4c4c (40 bytes; 1 call site
//!   @ 0x080bbbd4, passing the record stored by the spawn front-end).
//!   NULL is a no-op; otherwise gateway delete (thunk 0x08037f80 -> ROM
//!   0x2200427c, service 0x18 with the id), `os_free(rec->stack)`, tail
//!   `os_free(rec)`. Ghidra's FUN_080b4c4c C is misleading — it inlines
//!   the whole os_free/heap chain.
//! - `task_notify` — `FUN_08060f80` @ 0x08060f80 (72 bytes; 1 call site,
//!   `kernel_running` @ 0x0809444c — ported in kernel/sync_mutex.rs,
//!   which hooks this as `notify`). Returns 0 while the kernel-started
//!   byte @ 0x089ca848 is clear. Otherwise, when the current task's
//!   context word (0x0805665c) is still 0, it registers the current task
//!   (0x080865e8, with the callback pointer argument), fetches the task's
//!   context block (0x080cb828) and installs a fresh 100-entry queue pool
//!   (0x0807a080) at context+0x1c; returns 1.
//!
//! # Dispatch design (house pattern)
//!
//! ROM gateway services and the out-of-range RAM helpers route through
//! `TASK_HOOKS`. Already-ported dependencies are wired directly:
//! `memzero_aligned` and `strncpy` are plain calls, the heap slots default
//! to the real `os_malloc`/`os_free` (kernel/os_heap.rs), and the
//! `kernel_started` slot defaults to reading sync_mutex's
//! `KERNEL_STARTED` byte (single source of truth for 0x089ca848; a hook
//! slot so the notify tests don't race sync_mutex's). Default stubs:
//! id alloc spins (no kernel, no ids), `map_priority` is the identity
//! (exactly the original switch's default arm), `current_task_ctx`
//! returns a static dummy block so a mis-sequenced notify cannot fault,
//! everything else no-ops.
//!
//! Also here — the current-task query pair:
//!
//! - `current_task_record` — `FUN_080565f0` @ 0x080565f0 (96 bytes).
//!   Asks the gateway for the current task record (thunk 0x08037e58 ->
//!   ROM 0x22003ec4, service 40, argument 0). When the kernel knows no
//!   record (boot/foreign contexts), lazily claims a slot from a static
//!   pool of 0x3c task records (counter @ 0x089cc8f4, pool @ 0x08ac5ccc):
//!   `rec->id` comes from thunk 0x08037e60 called with the post-increment
//!   counter value (the thunk 0x08037e60 target ROM 0x22003eb0 is
//!   catalogued as the UNVERIFIED "size_to_class" — this call site is
//!   evidence it is really an id/handle helper), `entry`/`context`/the
//!   name's first byte are zeroed (ONLY those — no full memzero), and the
//!   record is gateway-registered with id 0 (`mov r0, #0` before the
//!   0x08037e38 call — faithful quirk). A full pool returns NULL.
//! - `current_task_context_word` — `FUN_0805665c` @ 0x0805665c
//!   (20 bytes). `current_task_record()->context` or 0 — the word
//!   sync_mutex's `current_task_id` hook reads (the "id" is really the
//!   caller's context record pointer).
//! - `task_spawn` — `FUN_0807a15c` @ 0x0807a15c (196 bytes; 2 bl call
//!   sites, 0x080e87a8 / 0x080e9e9c) — the spawn front-end and sole
//!   task_create caller. Maps the priority-flag argument (0/8/0x10/
//!   0x18/0x20/0x40/0x80/0xc0/0x100 -> level 0..8, other values below
//!   0x10 -> 1, at or above -> 3), packs the caller-owned `SpawnRecord`
//!   {name, entry, flags, arg, hook-or-default @ +0x14} and calls
//!   `task_create(SPAWN_TRAMPOLINE, level, stack_size, record, name)`,
//!   storing the returned `TaskRecord` at record+0x10. Its third
//!   argument is dead (r2 is overwritten with the stack size before
//!   use). Returns 0.
//! - `queue_pool_create` — `FUN_0807a080` @ 0x0807a080 (72 bytes; 22 bl
//!   call sites, among them task_notify @ 0x08060fb8). One tag-10
//!   allocation of `capacity * 0x14 + 0x48` bytes — the 0x48-byte pool
//!   header (kernel/mqueue.rs `QueuePool`) followed by the node array —
//!   then the (unported) initializer `FUN_0809eab8` lays it out:
//!   `pool_init(capacity, base + 0x48, base)`, degraded to
//!   `(0, NULL, base)` for `capacity < 1`. Returns the base unchecked.
//! - `register_current_task` — `FUN_080865e8` @ 0x080865e8 (168 bytes;
//!   2 bl call sites: task_notify @ 0x08060fa8 and 0x080e873c). Attaches
//!   a `NameNode` to the current task. The registration block @
//!   0x089ca848 (pointer literal @ 0x08086690) is {byte +0x00: the
//!   kernel-started flag — the SAME byte sync_mutex models as
//!   `KERNEL_STARTED`; +0x08: lock semaphore slot; +0x0c: pre-allocated
//!   node cache}. Before the kernel starts the node is freshly allocated
//!   (0x08093870, unported) with NO locking; after, the lock is taken
//!   and the cached node consumed. Then: node->task =
//!   current_task_record(); `current_task_link_node` stores the node
//!   into the record's context word; a nonzero `name` argument is
//!   duplicated into a tag-7 heap block (unguarded strlen 0x08392478 +
//!   0x080eb67c + strcpy 0x08030ff4) at node+0. Finally the lock is
//!   taken if it was not already, the cache is refilled when empty, and
//!   the lock is released (tail sem_signal). NOTE the faithful oddity:
//!   kernel_running's notify chain passes the CODE address 0x083e2e38 as
//!   `name`, so the "name" duplicated is whatever bytes live there up to
//!   the first NUL.
//! - `current_task_link_node` — `FUN_080568d0` @ 0x080568d0 (24 bytes;
//!   2 bl call sites: 0x0807f870 and register_current_task @
//!   0x08086634). `current_task_record()->context = node`; no record is
//!   a no-op.
//! - `current_task_ctx_block` — `FUN_080cb828` @ 0x080cb828 (20 bytes;
//!   46 bl call sites). `kernel_running()` (ported, kernel/sync_mutex.rs)
//!   returns the current task's context word — really the task's
//!   `NameNode` pointer — and this returns the node's context block at
//!   +0x0c, or 0 when there is no task. `TASK_HOOKS.current_task_ctx`
//!   defaults to this port; the `kernel_running_node` slot types the
//!   query's result as the pointer it is (cast in the default adapter).
//! - `kernel_yield` — `FUN_080568fc` @ 0x080568fc (8 bytes;
//!   `mov r0, #0; b 0x08037e98` -> ROM 0x22004260). The stock yield-like
//!   service call behind condvar.rs's `task_yield`/`task_yield_thunk`
//!   wrappers (their `CONDVAR_HOOKS.task_yield` slot is this function);
//!   the ROM result passes through to the caller.
//!
//! # Simplifications / deviations
//!
//! - The record is zeroed with the ported `memzero_aligned` over
//!   `size_of::<TaskRecord>()` — 0x44 on the ARM target (const-asserted),
//!   wider on 64-bit hosts where the pointer fields grow.
//! - `entry`/`context` are opaque machine words (`usize`), never called
//!   or dereferenced here, exactly like the original.
//! - Struct byte offsets (+0x1c in `TaskCtx`, +0x40 in `TaskRecord`) are
//!   exact only on the 32-bit target; host tests use field accesses.
//! - The static task-record pool and its counter live in osos RAM
//!   (0x08ac5ccc / 0x089cc8f4); the port substitutes crate statics, like
//!   sync_sem's `ISR_SEM_SLOT`.
//! - `TASK_HOOKS.current_task_context` defaults to the ported
//!   `current_task_context_word` (real wiring, not a stub).
//! - The registration block's lock-semaphore slot (0x089ca850) and node
//!   cache (0x089ca854) are the crate statics `REGISTER_LOCK_SEM` /
//!   `REGISTER_NODE_CACHE`; the block's flag byte (0x089ca848) stays
//!   sync_mutex's `KERNEL_STARTED`, read through the `kernel_started`
//!   hook — one source of truth per original address.
//! - The `register_current_task` hook slot types its argument as the
//!   string pointer it is used as (`*const u8`); task_notify casts its
//!   opaque callback word at the call.

use crate::kernel::sync_sem::SemHandle;
use crate::libc::memzero::memzero_aligned;
use crate::libc::strcpy::strcpy;
use crate::libc::strncpy::strncpy;

/// Capacity of the record's name field (the original strncpy length
/// `mov r2, #0x31`).
pub const TASK_NAME_CAP: usize = 0x31;

/// Opaque word the original passes as the 5th argument of the gateway
/// task init — the literal @ 0x08056468 = 0x0809c5c8. Falls inside the
/// mutex-delete helper's body, so it is NOT an entry point; purpose
/// unverified (kept verbatim, never dereferenced).
pub const TASK_INIT_WORD: usize = 0x0809_c5c8;

/// Task record (0x44 bytes on target — see the module header).
#[repr(C)]
pub struct TaskRecord {
    /// +0x00: kernel object id.
    pub id: u32,
    /// +0x04: entry trampoline (opaque word).
    pub entry: usize,
    /// +0x08: caller context record (opaque word).
    pub context: usize,
    /// +0x0c: task name (strncpy semantics: NUL-padded when short,
    /// unterminated when truncated — the forced `name_nul` covers that).
    pub name: [u8; TASK_NAME_CAP],
    /// +0x3d: forced NUL terminator.
    pub name_nul: u8,
    /// +0x3e: alignment padding.
    pub _pad: [u8; 2],
    /// +0x40: heap-allocated stack.
    pub stack: *mut u8,
}

// The original allocates and zeroes exactly 0x44 bytes.
#[cfg(target_pointer_width = "32")]
const _TASK_RECORD_SIZE_CHECK: [u8; 0x44] = [0; core::mem::size_of::<TaskRecord>()];

/// Per-task context block (0x080cb828's result). Only the word
/// `task_notify` writes is named; +0x00..+0x1c belong to the owner.
#[repr(C)]
pub struct TaskCtx {
    /// +0x00..+0x1c: owner fields, untouched here.
    _pad: [usize; 7],
    /// +0x1c: queue pool installed by `task_notify`.
    pub queue_pool: *mut u8,
}

/// Per-task registration node (0x18 bytes, tag-5 heap allocation by the
/// unported name-node allocator @ 0x08093870, which also creates the
/// node's 0x54-byte context block). A task's `TaskRecord::context` word
/// points at its node — the "current task id" the kernel_running query
/// returns is really this pointer.
#[repr(C)]
pub struct NameNode {
    /// +0x00: task-name string (the allocator seeds a default pointer;
    /// `register_current_task` overwrites it with a tag-7 heap copy).
    pub name: *mut u8,
    /// +0x04: allocator-zeroed, untouched here.
    pub _x04: usize,
    /// +0x08: allocator-zeroed, untouched here.
    pub _x08: usize,
    /// +0x0c: the task's context block (`current_task_ctx_block`'s
    /// result; `task_notify` installs the queue pool at ctx+0x1c).
    pub ctx: *mut TaskCtx,
    /// +0x10: `TaskRecord` installed by `register_current_task`.
    pub task: *mut TaskRecord,
    /// +0x14: allocator-zeroed, untouched here.
    pub _x14: usize,
}

// The original node is 6 words (allocated as 0x18 bytes).
#[cfg(target_pointer_width = "32")]
const _NAME_NODE_SIZE_CHECK: [u8; 0x18] = [0; core::mem::size_of::<NameNode>()];

impl NameNode {
    /// Const-init template (tests and the default-alloc scratch node).
    pub const ZERO: NameNode = NameNode {
        name: core::ptr::null_mut(),
        _x04: 0,
        _x08: 0,
        ctx: core::ptr::null_mut(),
        task: core::ptr::null_mut(),
        _x14: 0,
    };
}

/// Capacity of the queue pool `task_notify` installs (`mov r0, #0x64`).
const NOTIFY_POOL_CAPACITY: i32 = 100;

/// ROM gateway services and unported RAM helpers this module depends on.
#[derive(Clone, Copy)]
pub struct TaskHooks {
    /// Thunk 0x08037e28 -> ROM 0x22003b6c: gateway service 0x17, returns
    /// a fresh kernel object id.
    pub task_id_alloc: unsafe extern "C" fn() -> u32,
    /// `FUN_080e4348` @ 0x080e4348: priority level -> RTXC priority
    /// (0->0x7e, 1->0x3c, 2->0x34, 3->0x33, 4->0x31, 5->0x30, 6->10,
    /// 7->9, 8->8, default -> input). Out of this port's claim range.
    pub map_priority: unsafe extern "C" fn(level: u32) -> u32,
    /// Thunk 0x08037e30 -> ROM 0x22003c98: task init (aligns the size up
    /// to 8 internally; `init_word` is the opaque 5th argument).
    pub task_init:
        unsafe extern "C" fn(id: u32, prio: u32, stack: *mut u8, stack_size: usize, init_word: usize),
    /// Thunk 0x08037e38 -> ROM 0x22003d00: gateway service 41, registers
    /// the record for the id.
    pub task_register: unsafe extern "C" fn(id: u32, rec: *mut TaskRecord),
    /// `FUN_0806331c` @ 0x0806331c: {id, name} table insert (0x50 slots @
    /// *0x08063358); returns 1 on success, 0 when full — discarded.
    /// Defaults to the ported `task_name_table_insert`.
    pub name_register: unsafe extern "C" fn(id: u32, name: *const u8) -> u32,
    /// Thunk 0x08037f78 -> ROM 0x22003e00: gateway service 0x15 (start).
    pub rom_task_start: unsafe extern "C" fn(id: u32),
    /// Thunk 0x08037f80 -> ROM 0x2200427c: gateway service 0x18 (delete).
    pub rom_task_delete: unsafe extern "C" fn(id: u32),
    /// Tag-0 heap alloc @ 0x080769b8 — defaults to the real `os_malloc`.
    pub heap_alloc: unsafe extern "C" fn(size: usize) -> *mut u8,
    /// Tag-0 heap free @ 0x080f151c — defaults to the real `os_free`.
    pub heap_free: unsafe extern "C" fn(ptr: *mut u8),
    /// Kernel-started byte @ 0x089ca848 — defaults to reading
    /// sync_mutex's `KERNEL_STARTED`.
    pub kernel_started: unsafe extern "C" fn() -> u32,
    /// Thunk 0x08037e58 -> ROM 0x22003ec4: gateway service 40 — the
    /// kernel's current task record, NULL when it has none. The original
    /// always passes 0.
    pub rom_current_task: unsafe extern "C" fn(arg: u32) -> *mut TaskRecord,
    /// Thunk 0x08037e60 -> ROM 0x22003eb0: id/handle for a freshly
    /// claimed pool slot, called with the post-increment counter value
    /// (catalogued as the unverified "size_to_class" in thunks.rs).
    pub rom_slot_id: unsafe extern "C" fn(slot: u32) -> u32,
    /// `FUN_0805665c` @ 0x0805665c: the current task's context word
    /// (record +0x08), 0 when absent. Defaults to the ported
    /// `current_task_context_word`.
    pub current_task_context: unsafe extern "C" fn() -> usize,
    /// `FUN_080865e8` @ 0x080865e8: register the current task under the
    /// given name pointer. Defaults to the ported
    /// `register_current_task`.
    pub register_current_task: unsafe extern "C" fn(name: *const u8),
    /// Tagged retailOS allocator `FUN_080eb67c` @ 0x080eb67c — defaults
    /// to the real `malloc_wrapper` (heap/veneers.rs).
    pub tagged_alloc: unsafe extern "C" fn(size: usize, tag: usize) -> *mut u8,
    /// Unported name-node allocator `FUN_08093870` @ 0x08093870
    /// (0x18-byte tag-5 node plus its 0x54-byte context block).
    pub name_node_alloc: unsafe extern "C" fn() -> *mut NameNode,
    /// sem_wait `FUN_08056510` @ 0x08056510 — defaults to the real port
    /// (kernel/sync_sem.rs). A slot so host tests can observe the
    /// register lock without racing sync_sem's own mock table.
    pub sem_wait: unsafe extern "C" fn(sem: SemHandle),
    /// sem_signal `FUN_08056710` @ 0x08056710 — same policy.
    pub sem_signal: unsafe extern "C" fn(sem: SemHandle),
    /// `FUN_080cb828` @ 0x080cb828: the current task's context block.
    /// Defaults to the ported `current_task_ctx_block`.
    pub current_task_ctx: unsafe extern "C" fn() -> *mut TaskCtx,
    /// `kernel_running` @ 0x0809444c (ported in kernel/sync_mutex.rs).
    /// Its "current task id" result is really the task's `NameNode`
    /// pointer (the context word), so this slot types it as the pointer;
    /// the default adapter casts the ported query's `i32` (exact on the
    /// 32-bit target).
    pub kernel_running_node: unsafe extern "C" fn() -> *mut NameNode,
    /// `FUN_0807a080` @ 0x0807a080: allocate a queue pool of `capacity`
    /// 20-byte entries (tag-10 heap allocation). Defaults to the ported
    /// `queue_pool_create`.
    pub queue_pool_create: unsafe extern "C" fn(capacity: i32) -> *mut u8,
    /// Unported pool initializer `FUN_0809eab8` @ 0x0809eab8: lays out
    /// the 0x48-byte pool header (lock semaphore, condvars, free list of
    /// the `capacity` nodes at `nodes`) — see kernel/mqueue.rs's
    /// `QueuePool` for the header model.
    pub pool_init: unsafe extern "C" fn(capacity: i32, nodes: *mut u8, pool: *mut u8),
    /// Thunk 0x08037e98 -> ROM 0x22004260: the yield-like kernel service
    /// (exact RTXC op unidentified; always called with 0 here).
    pub rom_yield: unsafe extern "C" fn(arg: u32) -> i32,
}

/// Default stub: no kernel, no object ids — spin (create cannot succeed).
unsafe extern "C" fn missing_id_alloc() -> u32 {
    loop {}
}

/// task_priority_map — original: `FUN_080e4348` @ 0x080e4348 (120 bytes).
///
/// Pure jump-table switch mapping a task level 0..=8 to its RTXC
/// priority; anything else falls through the `cmp r0, #8 / addls pc`
/// guard and returns unchanged. 1 call site (task_create @ 0x08056404).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_priority_map(level: u32) -> u32 {
    match level {
        0 => 0x7e,
        1 => 0x3c,
        2 => 0x34,
        3 => 0x33,
        4 => 0x31,
        5 => 0x30,
        6 => 10,
        7 => 9,
        8 => 8,
        other => other,
    }
}

unsafe extern "C" fn missing_task_init(
    _id: u32,
    _prio: u32,
    _stack: *mut u8,
    _stack_size: usize,
    _init_word: usize,
) {
}

unsafe extern "C" fn missing_task_register(_id: u32, _rec: *mut TaskRecord) {}

/// Capacity of the task-name table (`cmp r2, #0x50`).
pub const TASK_NAME_TABLE_CAP: usize = 0x50;

/// Task-name table entry (8-byte stride: `lsl #0x3`). `id` 0 marks a
/// free slot.
#[repr(C)]
pub struct NameEntry {
    /// +0x00: kernel object id (0 = free).
    pub id: u32,
    /// +0x04: name pointer stored by the insert (NOT copied).
    pub name: *const u8,
}

impl NameEntry {
    const FREE: NameEntry = NameEntry {
        id: 0,
        name: core::ptr::null(),
    };
}

/// Original: 0x50-entry table @ 0x08a10870 (RAM, reached through the
/// pointer literal @ 0x08063358); crate static in the port.
static mut TASK_NAME_TABLE: [NameEntry; TASK_NAME_TABLE_CAP] =
    [NameEntry::FREE; TASK_NAME_TABLE_CAP];

/// task_name_table_insert — original: `FUN_0806331c` @ 0x0806331c
/// (60 bytes; 1 call site, task_create @ 0x0805643c).
///
/// Linear scan of the {id, name} table: the first slot whose id matches
/// `id` (re-register) or is 0 (free) gets `{id, name}`; returns 1, or 0
/// when the table is full. Faithful quirk: inserting id 0 stores into
/// the first free slot but leaves it looking free (id stays 0), so the
/// slot is reclaimed by the next insert.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_name_table_insert(id: u32, name: *const u8) -> u32 {
    for i in 0..TASK_NAME_TABLE_CAP {
        let entry = core::ptr::addr_of_mut!(TASK_NAME_TABLE[i]);
        let slot_id = (*entry).id;
        if slot_id == id || slot_id == 0 {
            (*entry).id = id;
            (*entry).name = name;
            return 1;
        }
    }
    0
}

unsafe extern "C" fn missing_rom_task_op(_id: u32) {}

/// Default: the crate's model of the kernel-started byte @ 0x089ca848.
unsafe extern "C" fn read_kernel_started() -> u32 {
    core::ptr::addr_of!(crate::kernel::sync_mutex::KERNEL_STARTED).read_volatile() as u32
}

/// Default stub: the kernel knows no current task — the lazy pool path
/// then takes over, exactly what happens pre-kernel in the original.
unsafe extern "C" fn missing_rom_current_task(_arg: u32) -> *mut TaskRecord {
    core::ptr::null_mut()
}

/// Default stub: no kernel, no handles — 0.
unsafe extern "C" fn missing_rom_slot_id(_slot: u32) -> u32 {
    0
}

/// Scratch node the default name-node-alloc stub hands out (the real
/// allocator @ 0x08093870 is unported), so a mis-wired registration
/// scribbles on scratch instead of faulting.
static mut DUMMY_NAME_NODE: NameNode = NameNode::ZERO;

unsafe extern "C" fn missing_name_node_alloc() -> *mut NameNode {
    core::ptr::addr_of_mut!(DUMMY_NAME_NODE)
}

/// Default adapter for `kernel_running_node`: the ported query returns
/// the node pointer as an `i32` "task id" — cast it back. Exact on the
/// 32-bit target; host tests mock the slot instead of relying on it.
unsafe extern "C" fn kernel_running_node_adapter() -> *mut NameNode {
    crate::kernel::sync_mutex::kernel_running() as usize as *mut NameNode
}

unsafe extern "C" fn missing_pool_init(_capacity: i32, _nodes: *mut u8, _pool: *mut u8) {}

/// Default stub: yielding without a scheduler is a no-op reporting 0.
unsafe extern "C" fn missing_rom_yield(_arg: u32) -> i32 {
    0
}

/// Shipped defaults — see the module header for the wiring rationale.
pub const DEFAULT_TASK_HOOKS: TaskHooks = TaskHooks {
    task_id_alloc: missing_id_alloc,
    map_priority: task_priority_map,
    task_init: missing_task_init,
    task_register: missing_task_register,
    name_register: task_name_table_insert,
    rom_task_start: missing_rom_task_op,
    rom_task_delete: missing_rom_task_op,
    heap_alloc: crate::kernel::os_heap::os_malloc,
    heap_free: crate::kernel::os_heap::os_free,
    kernel_started: read_kernel_started,
    rom_current_task: missing_rom_current_task,
    rom_slot_id: missing_rom_slot_id,
    current_task_context: current_task_context_word,
    register_current_task,
    tagged_alloc: crate::heap::veneers::malloc_wrapper,
    name_node_alloc: missing_name_node_alloc,
    sem_wait: crate::kernel::sync_sem::sem_wait,
    sem_signal: crate::kernel::sync_sem::sem_signal,
    current_task_ctx: current_task_ctx_block,
    kernel_running_node: kernel_running_node_adapter,
    queue_pool_create,
    pool_init: missing_pool_init,
    rom_yield: missing_rom_yield,
};

/// The active hook table. Written once at init on target; host tests
/// serialize access.
pub static mut TASK_HOOKS: TaskHooks = DEFAULT_TASK_HOOKS;

/// Reads the hook table (volatile — see sync_sem.rs).
#[inline(always)]
fn hooks() -> TaskHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TASK_HOOKS)) }
}

/// task_create — original: `FUN_080563a0` @ 0x080563a0 (200 bytes).
///
/// Allocates id, stack and record; fills the record (zeroed, name
/// strncpy'd + NUL-forced); runs the gateway init/register pair and the
/// name-table insert; starts the task; returns the record. Allocation
/// results are not NULL-checked (faithful).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_create(
    entry: usize,
    priority: u32,
    stack_size: usize,
    context: usize,
    name: *const u8,
) -> *mut TaskRecord {
    let h = hooks();
    let id = (h.task_id_alloc)();
    let stack = (h.heap_alloc)(stack_size);
    let rec = (h.heap_alloc)(core::mem::size_of::<TaskRecord>()) as *mut TaskRecord;
    memzero_aligned(rec as *mut u8, core::mem::size_of::<TaskRecord>());
    (*rec).stack = stack;
    (*rec).id = id;
    (*rec).entry = entry;
    (*rec).context = context;
    strncpy((*rec).name.as_mut_ptr(), name, TASK_NAME_CAP);
    (*rec).name_nul = 0;
    let prio = (h.map_priority)(priority);
    (h.task_init)(id, prio, stack, stack_size, TASK_INIT_WORD);
    (h.task_register)(id, rec);
    (h.name_register)(id, (*rec).name.as_ptr());
    task_start(entry, priority, stack_size, context, name, id, prio);
    rec
}

/// task_start — original: `FUN_080b4c44` @ 0x080b4c44 (8 bytes).
///
/// `ldr r0, [sp, #4]; b 0x08037f78` — forwards its sixth argument (the
/// task id) to gateway service 0x15, ignoring every other argument.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_start(
    _entry: usize,
    _priority: u32,
    _stack_size: usize,
    _context: usize,
    _name: *const u8,
    id: u32,
    _mapped_priority: u32,
) {
    (hooks().rom_task_start)(id);
}

/// task_destroy — original: `FUN_080b4c4c` @ 0x080b4c4c (40 bytes).
///
/// NULL is a no-op; otherwise gateway delete on the id, free the stack,
/// free the record.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_destroy(rec: *mut TaskRecord) {
    if rec.is_null() {
        return;
    }
    let h = hooks();
    (h.rom_task_delete)((*rec).id);
    (h.heap_free)((*rec).stack);
    (h.heap_free)(rec as *mut u8);
}

/// Capacity of the static current-task record pool (`cmp r0, #0x3c`).
pub const TASK_POOL_CAP: usize = 0x3c;

impl TaskRecord {
    /// Const-init template for the static pool.
    const ZERO: TaskRecord = TaskRecord {
        id: 0,
        entry: 0,
        context: 0,
        name: [0; TASK_NAME_CAP],
        name_nul: 0,
        _pad: [0; 2],
        stack: core::ptr::null_mut(),
    };
}

/// Original: claimed-slot counter @ 0x089cc8f4 (never decremented).
static mut TASK_POOL_COUNT: u32 = 0;

/// Original: pool of 0x3c task records @ 0x08ac5ccc (0x3c * 0x44 bytes).
static mut TASK_POOL: [TaskRecord; TASK_POOL_CAP] = [TaskRecord::ZERO; TASK_POOL_CAP];

/// current_task_record — original: `FUN_080565f0` @ 0x080565f0 (96 bytes).
///
/// The kernel's current task record; when the kernel has none, lazily
/// claims a static pool slot (id from the ROM slot-id helper, only
/// `entry`/`context`/`name[0]` cleared, gateway-registered under id 0 —
/// all faithful). NULL once the pool is exhausted.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_task_record() -> *mut TaskRecord {
    let h = hooks();
    let rec = (h.rom_current_task)(0);
    if !rec.is_null() {
        return rec;
    }
    let count = core::ptr::addr_of!(TASK_POOL_COUNT).read();
    if count >= TASK_POOL_CAP as u32 {
        return core::ptr::null_mut();
    }
    let rec = core::ptr::addr_of_mut!(TASK_POOL[count as usize]);
    core::ptr::addr_of_mut!(TASK_POOL_COUNT).write(count + 1);
    (*rec).id = (h.rom_slot_id)(count + 1);
    (*rec).entry = 0;
    (*rec).context = 0;
    (*rec).name[0] = 0;
    (h.task_register)(0, rec);
    rec
}

/// current_task_context_word — original: `FUN_0805665c` @ 0x0805665c
/// (20 bytes).
///
/// `current_task_record()->context`, or 0 when there is no record.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_task_context_word() -> usize {
    let rec = current_task_record();
    if rec.is_null() {
        0
    } else {
        (*rec).context
    }
}

/// current_task_ctx_block — original: `FUN_080cb828` @ 0x080cb828
/// (20 bytes; 46 bl call sites).
///
/// `kernel_running()`'s "task id" result treated as the current task's
/// `NameNode` pointer; returns the node's context block (+0x0c), or NULL
/// when the kernel reports no task. This is the block `task_notify`
/// installs the queue pool into. (`TASK_HOOKS.current_task_ctx` defaults
/// to this port.)
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_task_ctx_block() -> *mut TaskCtx {
    let node = (hooks().kernel_running_node)();
    if node.is_null() {
        core::ptr::null_mut()
    } else {
        (*node).ctx
    }
}

/// Heap tag for the task-name duplicate (`mov r1, #0x7`).
const TAG_TASK_NAME: usize = 7;

/// Original: register-lock semaphore slot @ 0x089ca850 (registration
/// block +0x08). Crate static in the port; NULL until kernel bring-up
/// creates the semaphore, which makes the sem ops guarded no-ops.
static mut REGISTER_LOCK_SEM: SemHandle = core::ptr::null_mut();

/// Original: pre-allocated name-node cache @ 0x089ca854 (block +0x0c).
static mut REGISTER_NODE_CACHE: *mut NameNode = core::ptr::null_mut();

/// Unguarded C string length — the retailOS strlen @ 0x08392478 the
/// registration measures the name with (inlined, like stdio/semihost.rs;
/// volatile reads keep LLVM from re-recognizing the loop as `strlen`).
unsafe fn strlen_raw(mut s: *const u8) -> usize {
    let mut len = 0;
    while core::ptr::read_volatile(s) != 0 {
        len += 1;
        s = s.add(1);
    }
    len
}

/// current_task_link_node — original: `FUN_080568d0` @ 0x080568d0
/// (24 bytes; 2 bl call sites).
///
/// Stores the node into the current task record's context word; no
/// record is a no-op.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_task_link_node(node: *mut NameNode) {
    let rec = current_task_record();
    if !rec.is_null() {
        (*rec).context = node as usize;
    }
}

/// register_current_task — original: `FUN_080865e8` @ 0x080865e8
/// (168 bytes; 2 bl call sites).
///
/// Attaches a `NameNode` to the current task: pre-kernel the node is
/// freshly allocated without locking; post-kernel the register lock is
/// taken and the cached node consumed. The node gets the current task
/// record and is linked into the record's context word; a nonzero
/// `name` is duplicated into a tag-7 heap block at node+0. On the way
/// out the lock is taken if it was not already, the node cache refilled
/// when empty, and the lock released. No NULL check on the node
/// (faithful — an empty cache post-kernel faults like the original).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn register_current_task(name: *const u8) {
    let h = hooks();
    let started = (h.kernel_started)() != 0;
    let node = if started {
        (h.sem_wait)(core::ptr::addr_of!(REGISTER_LOCK_SEM).read());
        let cached = core::ptr::addr_of!(REGISTER_NODE_CACHE).read();
        core::ptr::addr_of_mut!(REGISTER_NODE_CACHE).write(core::ptr::null_mut());
        cached
    } else {
        (h.name_node_alloc)()
    };
    (*node).task = current_task_record();
    current_task_link_node(node);
    if !name.is_null() {
        let copy = (h.tagged_alloc)(strlen_raw(name) + 1, TAG_TASK_NAME);
        strcpy(copy, name);
        (*node).name = copy;
    }
    if !started {
        (h.sem_wait)(core::ptr::addr_of!(REGISTER_LOCK_SEM).read());
    }
    if core::ptr::addr_of!(REGISTER_NODE_CACHE).read().is_null() {
        core::ptr::addr_of_mut!(REGISTER_NODE_CACHE).write((h.name_node_alloc)());
    }
    (h.sem_signal)(core::ptr::addr_of!(REGISTER_LOCK_SEM).read());
}

/// Entry trampoline every spawned task starts in (literal @ 0x0807a224).
/// The address is real code but not a Ghidra function head (it falls
/// inside the 0x08074xxx region); it presumably unpacks the
/// `SpawnRecord` handed over as the task context. Kept verbatim, never
/// called on host.
pub const SPAWN_TRAMPOLINE: usize = 0x0807_4990;

/// Default for the record's +0x14 word when the caller passes 0
/// (literal @ 0x0807a220). Also mid-function code (0x0808327c inside
/// 0x08083xxx); purpose unverified — kept verbatim, never dereferenced.
pub const SPAWN_DEFAULT_HOOK: usize = 0x0808_327c;

/// Caller-owned record `task_spawn` packs and hands to the trampoline
/// as the task context (6 words on target).
#[repr(C)]
pub struct SpawnRecord {
    /// +0x00: task name (also passed to task_create for the record and
    /// name table).
    pub name: *const u8,
    /// +0x04: the caller's real entry point, run by the trampoline.
    pub entry: usize,
    /// +0x08: the raw priority-flag argument.
    pub flags: u32,
    /// +0x0c: opaque caller word (arg 5).
    pub arg: usize,
    /// +0x10: the created `TaskRecord`, stored after task_create.
    pub task: *mut TaskRecord,
    /// +0x14: opaque caller word (arg 8), `SPAWN_DEFAULT_HOOK` when 0.
    pub hook: usize,
}

/// task_spawn — original: `FUN_0807a15c` @ 0x0807a15c (196 bytes; 2 bl
/// call sites, 0x080e87a8 / 0x080e9e9c). The sole task_create caller.
///
/// Maps the priority-flag argument to a level (0->0, 8->1, 0x10->2,
/// 0x18->3, 0x20->4, 0x40->5, 0x80->6, 0xc0->7, 0x100->8; any other
/// value below 0x10 -> 1, at or above -> 3), packs the caller record
/// (name, entry, flags, arg, hook-or-default) and creates the task with
/// the trampoline as entry and the record as context. The created
/// `TaskRecord` lands in `record->task`. `_unused` (arg 3) is ignored —
/// the original overwrites r2 with the stack size before ever reading
/// it. Always returns 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_spawn(
    name: *const u8,
    entry: usize,
    _unused: usize,
    stack_size: usize,
    arg: usize,
    flags: u32,
    record: *mut SpawnRecord,
    hook: usize,
) -> u32 {
    let hook = if hook == 0 { SPAWN_DEFAULT_HOOK } else { hook };
    let level: u32 = match flags {
        0 => 0,
        8 => 1,
        0x10 => 2,
        0x18 => 3,
        0x20 => 4,
        0x40 => 5,
        0x80 => 6,
        0xc0 => 7,
        0x100 => 8,
        other if other < 0x10 => 1,
        _ => 3,
    };
    (*record).name = name;
    (*record).entry = entry;
    (*record).flags = flags;
    (*record).arg = arg;
    (*record).hook = hook;
    (*record).task = task_create(SPAWN_TRAMPOLINE, level, stack_size, record as usize, name);
    0
}

/// Heap tag for queue pools (`mov r1, #0xa`).
const TAG_QUEUE_POOL: usize = 10;

/// Queue-pool node stride (0x14 — kernel/mqueue.rs `QueueNode`).
const QUEUE_NODE_STRIDE: u32 = 0x14;

/// Queue-pool header size (0x48; the node array follows it).
const QUEUE_POOL_HEADER: u32 = 0x48;

/// queue_pool_create — original: `FUN_0807a080` @ 0x0807a080 (72 bytes;
/// 22 bl call sites, among them task_notify @ 0x08060fb8).
///
/// Allocates `capacity * 0x14 + 0x48` bytes (tag 10) — header plus node
/// array — and initializes the pool: `pool_init(capacity, base + 0x48,
/// base)`, degraded to `(0, NULL, base)` when `capacity < 1`. Returns
/// the base. Faithful quirks: the size is computed from the raw
/// (possibly negative) capacity in wrapping 32-bit arithmetic, and the
/// allocation is not NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queue_pool_create(capacity: i32) -> *mut u8 {
    let h = hooks();
    let size = (capacity as u32)
        .wrapping_mul(QUEUE_NODE_STRIDE)
        .wrapping_add(QUEUE_POOL_HEADER);
    let base = (h.tagged_alloc)(size as usize, TAG_QUEUE_POOL);
    if capacity > 0 {
        (h.pool_init)(capacity, base.add(QUEUE_POOL_HEADER as usize), base);
    } else {
        (h.pool_init)(0, core::ptr::null_mut(), base);
    }
    base
}

/// kernel_yield — original: `FUN_080568fc` @ 0x080568fc (8 bytes).
///
/// The stock yield service call: ROM 0x22004260 with argument 0, result
/// passed through. (condvar.rs's `CONDVAR_HOOKS.task_yield` routes here.)
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kernel_yield() -> i32 {
    (hooks().rom_yield)(0)
}

/// task_notify — original: `FUN_08060f80` @ 0x08060f80 (72 bytes).
///
/// Returns 0 while the kernel-started byte is clear. Otherwise, when the
/// current task has no context word yet, registers the current task under
/// `callback` and installs a fresh 100-entry queue pool into the task's
/// context block; returns 1.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_notify(callback: usize) -> u32 {
    let h = hooks();
    if (h.kernel_started)() == 0 {
        return 0;
    }
    if (h.current_task_context)() == 0 {
        (h.register_current_task)(callback as *const u8);
        let ctx = (h.current_task_ctx)();
        (*ctx).queue_pool = (h.queue_pool_create)(NOTIFY_POOL_CAPACITY);
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::null_mut;
    use std::sync::{Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    /// Serializes tests that swap the global hook table.
    static HOOKS_LOCK: Mutex<()> = Mutex::new(());

    /// Every arm of the original switch @ 0x080e4348, plus the default
    /// (identity) arm for levels outside 0..=8.
    #[test]
    fn priority_map_matches_the_original_switch() {
        const TABLE: [(u32, u32); 9] = [
            (0, 0x7e),
            (1, 0x3c),
            (2, 0x34),
            (3, 0x33),
            (4, 0x31),
            (5, 0x30),
            (6, 10),
            (7, 9),
            (8, 8),
        ];
        for (level, priority) in TABLE {
            assert_eq!(unsafe { task_priority_map(level) }, priority, "level {level}");
        }
        for level in [9, 10, 0x7e, u32::MAX] {
            assert_eq!(unsafe { task_priority_map(level) }, level, "default arm {level}");
        }
    }

    /// The shipped hook default is the real port, not the identity stub.
    #[test]
    fn priority_map_is_the_shipped_hook_default() {
        assert_eq!(unsafe { (DEFAULT_TASK_HOOKS.map_priority)(0) }, 0x7e);
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        IdAlloc,
        MapPriority(u32),
        Init {
            id: u32,
            prio: u32,
            stack: usize,
            stack_size: usize,
            init_word: usize,
        },
        Register {
            id: u32,
            rec: usize,
        },
        NameRegister {
            id: u32,
            name: usize,
        },
        RomStart(u32),
        RomDelete(u32),
        Alloc(usize),
        Free(usize),
        KernelStarted,
        CurrentTaskContext,
        RegisterCurrentTask(usize),
        CurrentTaskCtx,
        PoolCreate(u32),
        RomCurrentTask(u32),
        RomSlotId(u32),
        RomYield(u32),
        KernelRunningNode,
        TaggedAlloc { size: usize, tag: usize },
        NameNodeAlloc,
        SemWait(usize),
        SemSignal(usize),
        PoolInit { capacity: i32, nodes: usize, pool: usize },
    }

    static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());

    const MOCK_ID: u32 = 0x7a5c;

    /// Aligned backing storage for the two allocations task_create makes:
    /// first the stack, then the record.
    #[repr(align(8))]
    struct AllocArena {
        stack: [u8; 64],
        rec: [u8; core::mem::size_of::<TaskRecord>()],
    }
    static mut ARENA: AllocArena = AllocArena {
        stack: [0xa5; 64],
        rec: [0xa5; core::mem::size_of::<TaskRecord>()],
    };
    static mut NEXT_ALLOC_IS_STACK: bool = true;

    static mut KERNEL_STARTED_MOCK: u32 = 0;
    static mut TASK_CONTEXT_MOCK: usize = 0;
    static mut CTX_BLOCK: TaskCtx = TaskCtx {
        _pad: [0; 7],
        queue_pool: null_mut(),
    };
    static mut POOL_RET: *mut u8 = null_mut();

    unsafe extern "C" fn mock_id_alloc() -> u32 {
        CALLS.lock().unwrap().push(Call::IdAlloc);
        MOCK_ID
    }

    unsafe extern "C" fn mock_map_priority(level: u32) -> u32 {
        CALLS.lock().unwrap().push(Call::MapPriority(level));
        // Mimic the original's level 1 -> 0x3c so the mapped value is
        // distinguishable from the raw one.
        if level == 1 {
            0x3c
        } else {
            level
        }
    }

    unsafe extern "C" fn mock_init(id: u32, prio: u32, stack: *mut u8, stack_size: usize, init_word: usize) {
        CALLS.lock().unwrap().push(Call::Init {
            id,
            prio,
            stack: stack as usize,
            stack_size,
            init_word,
        });
    }

    unsafe extern "C" fn mock_register(id: u32, rec: *mut TaskRecord) {
        CALLS.lock().unwrap().push(Call::Register {
            id,
            rec: rec as usize,
        });
    }

    unsafe extern "C" fn mock_name_register(id: u32, name: *const u8) -> u32 {
        CALLS.lock().unwrap().push(Call::NameRegister {
            id,
            name: name as usize,
        });
        1
    }

    unsafe extern "C" fn mock_rom_start(id: u32) {
        CALLS.lock().unwrap().push(Call::RomStart(id));
    }

    unsafe extern "C" fn mock_rom_delete(id: u32) {
        CALLS.lock().unwrap().push(Call::RomDelete(id));
    }

    unsafe extern "C" fn mock_alloc(size: usize) -> *mut u8 {
        CALLS.lock().unwrap().push(Call::Alloc(size));
        if NEXT_ALLOC_IS_STACK {
            NEXT_ALLOC_IS_STACK = false;
            core::ptr::addr_of_mut!(ARENA.stack) as *mut u8
        } else {
            core::ptr::addr_of_mut!(ARENA.rec) as *mut u8
        }
    }

    unsafe extern "C" fn mock_free(ptr: *mut u8) {
        CALLS.lock().unwrap().push(Call::Free(ptr as usize));
    }

    unsafe extern "C" fn mock_kernel_started() -> u32 {
        CALLS.lock().unwrap().push(Call::KernelStarted);
        KERNEL_STARTED_MOCK
    }

    unsafe extern "C" fn mock_current_task_context() -> usize {
        CALLS.lock().unwrap().push(Call::CurrentTaskContext);
        TASK_CONTEXT_MOCK
    }

    unsafe extern "C" fn mock_register_current_task(name: *const u8) {
        CALLS.lock().unwrap().push(Call::RegisterCurrentTask(name as usize));
    }

    /// Node arena for the name-node-alloc mock (initial + refill).
    static mut NODE_ARENA: [NameNode; 2] = [NameNode::ZERO; 2];
    static mut NODE_ARENA_NEXT: usize = 0;

    unsafe extern "C" fn mock_name_node_alloc() -> *mut NameNode {
        CALLS.lock().unwrap().push(Call::NameNodeAlloc);
        let i = NODE_ARENA_NEXT;
        NODE_ARENA_NEXT += 1;
        core::ptr::addr_of_mut!(NODE_ARENA[i])
    }

    /// Byte buffer the tagged-alloc mock hands out (name duplicates).
    static mut NAME_BUF: [u8; 64] = [0; 64];

    unsafe extern "C" fn mock_tagged_alloc(size: usize, tag: usize) -> *mut u8 {
        CALLS.lock().unwrap().push(Call::TaggedAlloc { size, tag });
        core::ptr::addr_of_mut!(NAME_BUF) as *mut u8
    }

    unsafe extern "C" fn mock_sem_wait(sem: SemHandle) {
        CALLS.lock().unwrap().push(Call::SemWait(sem as usize));
    }

    unsafe extern "C" fn mock_sem_signal(sem: SemHandle) {
        CALLS.lock().unwrap().push(Call::SemSignal(sem as usize));
    }

    /// Pointer value mock_hooks seeds REGISTER_LOCK_SEM with (never
    /// dereferenced by the sem mocks).
    const MOCK_LOCK_SEM: usize = 0x5150;

    unsafe extern "C" fn mock_current_task_ctx() -> *mut TaskCtx {
        CALLS.lock().unwrap().push(Call::CurrentTaskCtx);
        core::ptr::addr_of_mut!(CTX_BLOCK)
    }

    unsafe extern "C" fn mock_pool_create(capacity: i32) -> *mut u8 {
        CALLS.lock().unwrap().push(Call::PoolCreate(capacity as u32));
        POOL_RET
    }

    unsafe extern "C" fn mock_pool_init(capacity: i32, nodes: *mut u8, pool: *mut u8) {
        CALLS.lock().unwrap().push(Call::PoolInit {
            capacity,
            nodes: nodes as usize,
            pool: pool as usize,
        });
    }

    /// Record the rom_current_task mock returns (NULL -> lazy pool path).
    static mut ROM_TASK_RET: *mut TaskRecord = null_mut();

    unsafe extern "C" fn mock_rom_current_task(arg: u32) -> *mut TaskRecord {
        CALLS.lock().unwrap().push(Call::RomCurrentTask(arg));
        ROM_TASK_RET
    }

    unsafe extern "C" fn mock_rom_slot_id(slot: u32) -> u32 {
        CALLS.lock().unwrap().push(Call::RomSlotId(slot));
        0x9000 + slot
    }

    unsafe extern "C" fn mock_rom_yield(arg: u32) -> i32 {
        CALLS.lock().unwrap().push(Call::RomYield(arg));
        -3
    }

    /// Node the kernel_running_node mock returns (NULL = no task).
    static mut RUNNING_NODE_RET: *mut NameNode = null_mut();

    unsafe extern "C" fn mock_kernel_running_node() -> *mut NameNode {
        CALLS.lock().unwrap().push(Call::KernelRunningNode);
        RUNNING_NODE_RET
    }

    fn mock_hooks() -> MutexGuard<'static, ()> {
        let guard = HOOKS_LOCK.lock().unwrap();
        unsafe {
            NEXT_ALLOC_IS_STACK = true;
            core::ptr::addr_of_mut!(ARENA).write(AllocArena {
                stack: [0xa5; 64],
                rec: [0xa5; core::mem::size_of::<TaskRecord>()],
            });
            KERNEL_STARTED_MOCK = 0;
            TASK_CONTEXT_MOCK = 0;
            CTX_BLOCK.queue_pool = null_mut();
            POOL_RET = null_mut();
            ROM_TASK_RET = null_mut();
            RUNNING_NODE_RET = null_mut();
            core::ptr::addr_of_mut!(TASK_POOL_COUNT).write(0);
            core::ptr::addr_of_mut!(TASK_NAME_TABLE)
                .write([NameEntry::FREE; TASK_NAME_TABLE_CAP]);
            NODE_ARENA_NEXT = 0;
            core::ptr::addr_of_mut!(NODE_ARENA).write([NameNode::ZERO; 2]);
            core::ptr::addr_of_mut!(NAME_BUF).write([0; 64]);
            core::ptr::addr_of_mut!(REGISTER_LOCK_SEM).write(MOCK_LOCK_SEM as SemHandle);
            core::ptr::addr_of_mut!(REGISTER_NODE_CACHE).write(null_mut());
            core::ptr::addr_of_mut!(TASK_HOOKS).write(TaskHooks {
                task_id_alloc: mock_id_alloc,
                map_priority: mock_map_priority,
                task_init: mock_init,
                task_register: mock_register,
                name_register: mock_name_register,
                rom_task_start: mock_rom_start,
                rom_task_delete: mock_rom_delete,
                heap_alloc: mock_alloc,
                heap_free: mock_free,
                kernel_started: mock_kernel_started,
                rom_current_task: mock_rom_current_task,
                rom_slot_id: mock_rom_slot_id,
                current_task_context: mock_current_task_context,
                register_current_task: mock_register_current_task,
                tagged_alloc: mock_tagged_alloc,
                name_node_alloc: mock_name_node_alloc,
                sem_wait: mock_sem_wait,
                sem_signal: mock_sem_signal,
                current_task_ctx: mock_current_task_ctx,
                kernel_running_node: mock_kernel_running_node,
                queue_pool_create: mock_pool_create,
                pool_init: mock_pool_init,
                rom_yield: mock_rom_yield,
            });
        }
        CALLS.lock().unwrap().clear();
        guard
    }

    fn drain() -> Vec<Call> {
        core::mem::take(&mut *CALLS.lock().unwrap())
    }

    /// PAD trailing bytes so strncpy's word paths may read past the NUL
    /// (PORTING.md rule 3).
    const NAME: &[u8] = b"mediaserverd\0PADPADPAD";

    #[test]
    fn create_fills_the_record_and_runs_the_gateway_sequence() {
        let _guard = mock_hooks();
        unsafe {
            let rec = task_create(0x0807_4990, 1, 0x40, 0xc0ffee, NAME.as_ptr());
            assert_eq!(rec as *mut u8, core::ptr::addr_of_mut!(ARENA.rec) as *mut u8);
            let stack = core::ptr::addr_of_mut!(ARENA.stack) as *mut u8;

            // Record contents.
            assert_eq!((*rec).id, MOCK_ID);
            assert_eq!((*rec).entry, 0x0807_4990);
            assert_eq!((*rec).context, 0xc0ffee);
            assert_eq!((*rec).stack, stack);
            let name_copy: [u8; TASK_NAME_CAP] = (*rec).name;
            assert_eq!(&name_copy[..12], b"mediaserverd");
            assert!(
                name_copy[12..].iter().all(|&b| b == 0),
                "strncpy NUL-pads the short name over the zeroed record"
            );
            assert_eq!((*rec).name_nul, 0);
            assert_eq!((*rec)._pad, [0; 2], "memzero covered the padding");

            // Call sequence.
            let rec_name = (*rec).name.as_ptr() as usize;
            assert_eq!(
                drain(),
                vec![
                    Call::IdAlloc,
                    Call::Alloc(0x40),
                    Call::Alloc(core::mem::size_of::<TaskRecord>()),
                    Call::MapPriority(1),
                    Call::Init {
                        id: MOCK_ID,
                        prio: 0x3c,
                        stack: stack as usize,
                        stack_size: 0x40,
                        init_word: TASK_INIT_WORD,
                    },
                    Call::Register {
                        id: MOCK_ID,
                        rec: rec as usize,
                    },
                    Call::NameRegister {
                        id: MOCK_ID,
                        name: rec_name,
                    },
                    Call::RomStart(MOCK_ID),
                ]
            );
        }
    }

    #[test]
    fn create_truncates_long_names_but_forces_the_terminator() {
        let _guard = mock_hooks();
        let long: [u8; TASK_NAME_CAP + 12] = [b'x'; TASK_NAME_CAP + 12];
        unsafe {
            let rec = task_create(0, 0, 16, 0, long.as_ptr());
            assert_eq!((*rec).name, [b'x'; TASK_NAME_CAP], "0x31 bytes copied, no NUL inside");
            assert_eq!((*rec).name_nul, 0, "the forced byte at +0x3d terminates it");
        }
    }

    #[test]
    fn start_forwards_only_the_sixth_argument() {
        let _guard = mock_hooks();
        unsafe {
            task_start(0xbad, 0xbad, 0xbad, 0xbad, core::ptr::null(), 0x1234, 0xbad);
            assert_eq!(drain(), vec![Call::RomStart(0x1234)]);
        }
    }

    #[test]
    fn destroy_deletes_then_frees_stack_and_record() {
        let _guard = mock_hooks();
        unsafe {
            let rec = core::ptr::addr_of_mut!(ARENA.rec) as *mut TaskRecord;
            (*rec).id = 0x55;
            (*rec).stack = core::ptr::addr_of_mut!(ARENA.stack) as *mut u8;
            task_destroy(rec);
            assert_eq!(
                drain(),
                vec![
                    Call::RomDelete(0x55),
                    Call::Free((*rec).stack as usize),
                    Call::Free(rec as usize),
                ]
            );
        }
    }

    #[test]
    fn destroy_null_is_a_no_op() {
        let _guard = mock_hooks();
        unsafe {
            task_destroy(null_mut());
            assert!(drain().is_empty());
        }
    }

    #[test]
    fn notify_returns_zero_before_the_kernel_starts() {
        let _guard = mock_hooks();
        unsafe {
            assert_eq!(task_notify(0x083e_2e38), 0);
            assert_eq!(drain(), vec![Call::KernelStarted]);
        }
    }

    #[test]
    fn notify_skips_registration_when_the_task_has_a_context() {
        let _guard = mock_hooks();
        unsafe {
            KERNEL_STARTED_MOCK = 1;
            TASK_CONTEXT_MOCK = 0xdead;
            assert_eq!(task_notify(0x083e_2e38), 1);
            assert_eq!(drain(), vec![Call::KernelStarted, Call::CurrentTaskContext]);
        }
    }

    #[test]
    fn notify_registers_and_installs_the_pool() {
        let _guard = mock_hooks();
        unsafe {
            KERNEL_STARTED_MOCK = 1;
            let mut pool_word = 0u8;
            POOL_RET = &mut pool_word;
            assert_eq!(task_notify(0x083e_2e38), 1);
            assert_eq!(
                CTX_BLOCK.queue_pool, &mut pool_word as *mut u8,
                "the pool lands at context+0x1c"
            );
            assert_eq!(
                drain(),
                vec![
                    Call::KernelStarted,
                    Call::CurrentTaskContext,
                    Call::RegisterCurrentTask(0x083e_2e38),
                    Call::CurrentTaskCtx,
                    Call::PoolCreate(100),
                ]
            );
        }
    }

    #[test]
    fn yield_calls_the_rom_service_with_zero_and_passes_the_result() {
        let _guard = mock_hooks();
        unsafe {
            assert_eq!(kernel_yield(), -3);
            assert_eq!(drain(), vec![Call::RomYield(0)]);
        }
    }

    #[test]
    fn current_task_prefers_the_kernel_record() {
        let _guard = mock_hooks();
        unsafe {
            let mut kernel_rec = TaskRecord::ZERO;
            ROM_TASK_RET = &mut kernel_rec;
            assert_eq!(current_task_record(), &mut kernel_rec as *mut TaskRecord);
            assert_eq!(drain(), vec![Call::RomCurrentTask(0)]);
            assert_eq!(core::ptr::addr_of!(TASK_POOL_COUNT).read(), 0, "pool untouched");
        }
    }

    #[test]
    fn current_task_lazily_claims_pool_slots() {
        let _guard = mock_hooks();
        unsafe {
            // First claim: slot 0, id from rom_slot_id(1).
            let rec = current_task_record();
            assert_eq!(rec, core::ptr::addr_of_mut!(TASK_POOL[0]));
            assert_eq!((*rec).id, 0x9001);
            assert_eq!((*rec).entry, 0);
            assert_eq!((*rec).context, 0);
            assert_eq!((*rec).name[0], 0);
            assert_eq!(
                drain(),
                vec![
                    Call::RomCurrentTask(0),
                    Call::RomSlotId(1),
                    // Faithful quirk: registered under id 0, not rec->id.
                    Call::Register { id: 0, rec: rec as usize },
                ]
            );
            // Second claim advances to slot 1.
            let rec2 = current_task_record();
            assert_eq!(rec2, core::ptr::addr_of_mut!(TASK_POOL[1]));
            assert_eq!((*rec2).id, 0x9002);
            assert_eq!(core::ptr::addr_of!(TASK_POOL_COUNT).read(), 2);
        }
    }

    #[test]
    fn current_task_exhausted_pool_returns_null() {
        let _guard = mock_hooks();
        unsafe {
            core::ptr::addr_of_mut!(TASK_POOL_COUNT).write(TASK_POOL_CAP as u32);
            assert!(current_task_record().is_null());
            // Only the gateway probe ran; nothing was claimed/registered.
            assert_eq!(drain(), vec![Call::RomCurrentTask(0)]);
            assert_eq!(
                core::ptr::addr_of!(TASK_POOL_COUNT).read(),
                TASK_POOL_CAP as u32
            );
        }
    }

    #[test]
    fn context_word_comes_from_the_record() {
        let _guard = mock_hooks();
        unsafe {
            let mut kernel_rec = TaskRecord::ZERO;
            kernel_rec.context = 0xfeed;
            ROM_TASK_RET = &mut kernel_rec;
            assert_eq!(current_task_context_word(), 0xfeed);
            // Exhausted pool + no kernel record -> 0.
            ROM_TASK_RET = null_mut();
            core::ptr::addr_of_mut!(TASK_POOL_COUNT).write(TASK_POOL_CAP as u32);
            assert_eq!(current_task_context_word(), 0);
        }
    }

    // ---- task_name_table_insert (0x0806331c) -------------------------

    /// Reads slot i of the name table.
    unsafe fn name_slot(i: usize) -> (u32, *const u8) {
        let e = core::ptr::addr_of!(TASK_NAME_TABLE[i]);
        ((*e).id, (*e).name)
    }

    #[test]
    fn name_insert_claims_free_slots_in_order() {
        let _guard = mock_hooks();
        unsafe {
            assert_eq!(task_name_table_insert(0x11, 0x100 as *const u8), 1);
            assert_eq!(task_name_table_insert(0x22, 0x200 as *const u8), 1);
            assert_eq!(name_slot(0), (0x11, 0x100 as *const u8));
            assert_eq!(name_slot(1), (0x22, 0x200 as *const u8));
            assert_eq!(name_slot(2), (0, core::ptr::null()));
        }
    }

    #[test]
    fn name_insert_reuses_the_slot_of_a_matching_id() {
        let _guard = mock_hooks();
        unsafe {
            assert_eq!(task_name_table_insert(0x11, 0x100 as *const u8), 1);
            assert_eq!(task_name_table_insert(0x22, 0x200 as *const u8), 1);
            // Re-registering id 0x11 updates slot 0 in place.
            assert_eq!(task_name_table_insert(0x11, 0x999 as *const u8), 1);
            assert_eq!(name_slot(0), (0x11, 0x999 as *const u8));
            assert_eq!(name_slot(2), (0, core::ptr::null()), "no new slot claimed");
        }
    }

    #[test]
    fn name_insert_full_table_returns_zero() {
        let _guard = mock_hooks();
        unsafe {
            for i in 0..TASK_NAME_TABLE_CAP {
                assert_eq!(task_name_table_insert(1 + i as u32, 0x100 as *const u8), 1);
            }
            assert_eq!(
                task_name_table_insert(0x5000, 0x200 as *const u8),
                0,
                "0x50 distinct ids fill the table"
            );
            // A known id still succeeds in place.
            assert_eq!(task_name_table_insert(1, 0x300 as *const u8), 1);
            assert_eq!(name_slot(0), (1, 0x300 as *const u8));
        }
    }

    #[test]
    fn name_insert_id_zero_leaves_the_slot_free() {
        let _guard = mock_hooks();
        unsafe {
            // Faithful quirk: id 0 matches the "free" test, stores the
            // name, and leaves id 0 behind — still free.
            assert_eq!(task_name_table_insert(0, 0x700 as *const u8), 1);
            assert_eq!(name_slot(0), (0, 0x700 as *const u8));
            // The next insert reclaims the very same slot.
            assert_eq!(task_name_table_insert(0x33, 0x800 as *const u8), 1);
            assert_eq!(name_slot(0), (0x33, 0x800 as *const u8));
            assert_eq!(name_slot(1), (0, core::ptr::null()));
        }
    }

    #[test]
    fn name_insert_is_the_shipped_name_register_default() {
        assert_eq!(
            DEFAULT_TASK_HOOKS.name_register as usize,
            task_name_table_insert as usize
        );
    }

    // ---- register_current_task (0x080865e8) --------------------------

    #[test]
    fn register_before_kernel_start_allocates_without_locking() {
        let _guard = mock_hooks();
        unsafe {
            let mut rec = TaskRecord::ZERO;
            ROM_TASK_RET = &mut rec;
            register_current_task(core::ptr::null());
            let node = core::ptr::addr_of_mut!(NODE_ARENA[0]);
            assert_eq!((*node).task, &mut rec as *mut TaskRecord);
            assert_eq!(rec.context, node as usize, "node linked into the record");
            assert!((*node).name.is_null(), "no name to duplicate");
            assert_eq!(
                core::ptr::addr_of!(REGISTER_NODE_CACHE).read(),
                core::ptr::addr_of_mut!(NODE_ARENA[1]),
                "cache refilled with a fresh node"
            );
            assert_eq!(
                drain(),
                vec![
                    Call::KernelStarted,
                    Call::NameNodeAlloc,        // fresh node, NO lock yet
                    Call::RomCurrentTask(0),    // node->task
                    Call::RomCurrentTask(0),    // link (own record query)
                    Call::SemWait(MOCK_LOCK_SEM), // lock only at the end
                    Call::NameNodeAlloc,        // cache refill
                    Call::SemSignal(MOCK_LOCK_SEM),
                ]
            );
        }
    }

    #[test]
    fn register_after_kernel_start_consumes_the_cached_node() {
        let _guard = mock_hooks();
        unsafe {
            KERNEL_STARTED_MOCK = 1;
            let mut rec = TaskRecord::ZERO;
            ROM_TASK_RET = &mut rec;
            let mut cached = NameNode::ZERO;
            core::ptr::addr_of_mut!(REGISTER_NODE_CACHE).write(&mut cached);
            register_current_task(core::ptr::null());
            assert_eq!(cached.task, &mut rec as *mut TaskRecord);
            assert_eq!(rec.context, &mut cached as *mut NameNode as usize);
            assert_eq!(
                core::ptr::addr_of!(REGISTER_NODE_CACHE).read(),
                core::ptr::addr_of_mut!(NODE_ARENA[0]),
                "consumed cache was refilled"
            );
            assert_eq!(
                drain(),
                vec![
                    Call::KernelStarted,
                    Call::SemWait(MOCK_LOCK_SEM), // lock up front
                    Call::RomCurrentTask(0),
                    Call::RomCurrentTask(0),
                    Call::NameNodeAlloc, // refill only — no initial alloc
                    Call::SemSignal(MOCK_LOCK_SEM),
                ]
            );
        }
    }

    #[test]
    fn register_duplicates_the_name_into_a_tag7_block() {
        let _guard = mock_hooks();
        unsafe {
            let mut rec = TaskRecord::ZERO;
            ROM_TASK_RET = &mut rec;
            register_current_task(NAME.as_ptr());
            let node = core::ptr::addr_of_mut!(NODE_ARENA[0]);
            let buf = core::ptr::addr_of_mut!(NAME_BUF) as *mut u8;
            assert_eq!((*node).name, buf, "node points at the duplicate");
            assert_eq!(
                core::slice::from_raw_parts(buf as *const u8, 13),
                b"mediaserverd\0",
                "strcpy copied the string plus NUL"
            );
            let calls = drain();
            assert!(
                calls.contains(&Call::TaggedAlloc { size: 13, tag: 7 }),
                "strlen+1 bytes with tag 7: {calls:?}"
            );
        }
    }

    #[test]
    fn register_keeps_an_existing_cache() {
        let _guard = mock_hooks();
        unsafe {
            let mut rec = TaskRecord::ZERO;
            ROM_TASK_RET = &mut rec;
            // Pre-kernel path allocates its own node; the cache already
            // holds one, so no refill happens.
            let mut cached = NameNode::ZERO;
            core::ptr::addr_of_mut!(REGISTER_NODE_CACHE).write(&mut cached);
            register_current_task(core::ptr::null());
            assert_eq!(
                core::ptr::addr_of!(REGISTER_NODE_CACHE).read(),
                &mut cached as *mut NameNode,
                "existing cache untouched"
            );
            let calls = drain();
            assert_eq!(
                calls.iter().filter(|c| **c == Call::NameNodeAlloc).count(),
                1,
                "only the initial node allocation: {calls:?}"
            );
        }
    }

    #[test]
    fn link_node_stores_into_the_record_context() {
        let _guard = mock_hooks();
        unsafe {
            let mut rec = TaskRecord::ZERO;
            ROM_TASK_RET = &mut rec;
            let mut node = NameNode::ZERO;
            current_task_link_node(&mut node);
            assert_eq!(rec.context, &mut node as *mut NameNode as usize);
            // No record at all (kernel silent, pool exhausted): a no-op.
            ROM_TASK_RET = null_mut();
            core::ptr::addr_of_mut!(TASK_POOL_COUNT).write(TASK_POOL_CAP as u32);
            current_task_link_node(&mut node);
        }
    }

    // ---- task_spawn (0x0807a15c) -------------------------------------

    fn zero_spawn_record() -> SpawnRecord {
        SpawnRecord {
            name: core::ptr::null(),
            entry: 0,
            flags: 0,
            arg: 0,
            task: null_mut(),
            hook: 0,
        }
    }

    #[test]
    fn spawn_packs_the_record_and_creates_the_task() {
        let _guard = mock_hooks();
        let mut record = zero_spawn_record();
        unsafe {
            let r = task_spawn(
                NAME.as_ptr(),
                0x0812_3456, // real entry, run by the trampoline
                0xbad,       // dead argument
                0x40,
                0xa5a5,
                8, // -> level 1
                &mut record,
                0x0866_0000,
            );
            assert_eq!(r, 0);
            assert_eq!(record.name, NAME.as_ptr());
            assert_eq!(record.entry, 0x0812_3456);
            assert_eq!(record.flags, 8);
            assert_eq!(record.arg, 0xa5a5);
            assert_eq!(record.hook, 0x0866_0000, "nonzero arg 8 kept");
            assert_eq!(
                record.task as *mut u8,
                core::ptr::addr_of_mut!(ARENA.rec) as *mut u8,
                "task_create's record stored at +0x10"
            );
            // The spawned TaskRecord got the trampoline as entry and the
            // spawn record as context.
            let rec = record.task;
            assert_eq!((*rec).entry, SPAWN_TRAMPOLINE);
            assert_eq!((*rec).context, &mut record as *mut SpawnRecord as usize);
            let calls = drain();
            assert_eq!(calls[0], Call::IdAlloc, "task_create ran");
            assert!(
                calls.contains(&Call::MapPriority(1)),
                "flag 8 mapped to level 1 before the priority map: {calls:?}"
            );
        }
    }

    #[test]
    fn spawn_flag_to_level_table() {
        // Every explicit arm plus both default arms.
        const TABLE: [(u32, u32); 13] = [
            (0, 0),
            (8, 1),
            (0x10, 2),
            (0x18, 3),
            (0x20, 4),
            (0x40, 5),
            (0x80, 6),
            (0xc0, 7),
            (0x100, 8),
            (4, 1),      // below 0x10 -> 1
            (0xf, 1),    // below 0x10 -> 1
            (0x30, 3),   // at/above 0x10 -> 3
            (0x2000, 3), // at/above 0x10 -> 3
        ];
        for (flags, level) in TABLE {
            let _guard = mock_hooks();
            let mut record = zero_spawn_record();
            unsafe {
                task_spawn(NAME.as_ptr(), 0, 0, 16, 0, flags, &mut record, 1);
                let calls = drain();
                assert!(
                    calls.contains(&Call::MapPriority(level)),
                    "flags {flags:#x} -> level {level}: {calls:?}"
                );
            }
        }
    }

    #[test]
    fn spawn_zero_hook_takes_the_default() {
        let _guard = mock_hooks();
        let mut record = zero_spawn_record();
        unsafe {
            task_spawn(NAME.as_ptr(), 0, 0, 16, 0, 0, &mut record, 0);
            assert_eq!(record.hook, SPAWN_DEFAULT_HOOK);
        }
    }

    // ---- queue_pool_create (0x0807a080) ------------------------------

    #[test]
    fn pool_create_allocates_header_plus_nodes_with_tag_10() {
        let _guard = mock_hooks();
        unsafe {
            let base = queue_pool_create(100);
            let buf = core::ptr::addr_of_mut!(NAME_BUF) as *mut u8;
            assert_eq!(base, buf, "returns the allocation base");
            assert_eq!(
                drain(),
                vec![
                    Call::TaggedAlloc {
                        size: 100 * 0x14 + 0x48,
                        tag: 10
                    },
                    Call::PoolInit {
                        capacity: 100,
                        nodes: buf as usize + 0x48,
                        pool: buf as usize,
                    },
                ]
            );
        }
    }

    #[test]
    fn pool_create_zero_capacity_degrades_the_init() {
        let _guard = mock_hooks();
        unsafe {
            queue_pool_create(0);
            let buf = core::ptr::addr_of_mut!(NAME_BUF) as usize;
            assert_eq!(
                drain(),
                vec![
                    Call::TaggedAlloc { size: 0x48, tag: 10 },
                    Call::PoolInit {
                        capacity: 0,
                        nodes: 0,
                        pool: buf,
                    },
                ]
            );
        }
    }

    #[test]
    fn pool_create_negative_capacity_wraps_like_the_original() {
        let _guard = mock_hooks();
        unsafe {
            queue_pool_create(-1);
            let buf = core::ptr::addr_of_mut!(NAME_BUF) as usize;
            assert_eq!(
                drain(),
                vec![
                    // 0xffffffff * 0x14 + 0x48 (mod 2^32) = 0x34.
                    Call::TaggedAlloc { size: 0x34, tag: 10 },
                    Call::PoolInit {
                        capacity: 0,
                        nodes: 0,
                        pool: buf,
                    },
                ]
            );
        }
    }

    #[test]
    fn pool_create_is_the_shipped_queue_pool_default() {
        assert_eq!(
            DEFAULT_TASK_HOOKS.queue_pool_create as usize,
            queue_pool_create as usize
        );
    }

    // ---- current_task_ctx_block (0x080cb828) -------------------------

    #[test]
    fn ctx_block_is_null_when_the_kernel_reports_no_task() {
        let _guard = mock_hooks();
        unsafe {
            assert!(current_task_ctx_block().is_null());
            assert_eq!(drain(), vec![Call::KernelRunningNode]);
        }
    }

    #[test]
    fn ctx_block_comes_from_the_node() {
        let _guard = mock_hooks();
        unsafe {
            let mut ctx = TaskCtx {
                _pad: [0; 7],
                queue_pool: null_mut(),
            };
            let mut node = NameNode::ZERO;
            node.ctx = &mut ctx;
            RUNNING_NODE_RET = &mut node;
            assert_eq!(current_task_ctx_block(), &mut ctx as *mut TaskCtx);
            assert_eq!(drain(), vec![Call::KernelRunningNode]);
        }
    }

    #[test]
    fn default_wired_slots() {
        assert_eq!(
            DEFAULT_TASK_HOOKS.heap_alloc as usize,
            crate::kernel::os_heap::os_malloc as usize
        );
        assert_eq!(
            DEFAULT_TASK_HOOKS.heap_free as usize,
            crate::kernel::os_heap::os_free as usize
        );
        // The identity default matches the original priority map's
        // out-of-range arm.
        unsafe {
            assert_eq!((DEFAULT_TASK_HOOKS.map_priority)(0x1234), 0x1234);
        }
        // The context-word slot is wired to the ported query, not a stub.
        assert_eq!(
            DEFAULT_TASK_HOOKS.current_task_context as usize,
            current_task_context_word as usize
        );
        // The ctx-block slot is wired to the ported 0x080cb828.
        assert_eq!(
            DEFAULT_TASK_HOOKS.current_task_ctx as usize,
            current_task_ctx_block as usize
        );
        // The registration slot is wired to the ported 0x080865e8, and
        // its helpers default to the real ports.
        assert_eq!(
            DEFAULT_TASK_HOOKS.register_current_task as usize,
            register_current_task as usize
        );
        assert_eq!(
            DEFAULT_TASK_HOOKS.tagged_alloc as usize,
            crate::heap::veneers::malloc_wrapper as usize
        );
        assert_eq!(
            DEFAULT_TASK_HOOKS.sem_wait as usize,
            crate::kernel::sync_sem::sem_wait as usize
        );
        assert_eq!(
            DEFAULT_TASK_HOOKS.sem_signal as usize,
            crate::kernel::sync_sem::sem_signal as usize
        );
    }
}

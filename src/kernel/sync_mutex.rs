//! RAM-side mutex layer over the RTXC Quadros mask-ROM kernel, plus the
//! kernel-running query.
//!
//! - `mutex_create` — original: `FUN_080744a4` @ 0x080744a4 (28 bytes;
//!   87 call sites). Allocates a 4-byte semaphore cell through the
//!   cell-create thunk @ 0x8056724, stores it in the mutex and zeroes the
//!   word at +4. The thunk: when the heap "early boot" flag
//!   (`FUN_080bead8` @ 0x080bead8, a byte read at heap_ctx+0xb5) is
//!   nonzero the cell is the shared static cell @ 0x089cc8f8; otherwise
//!   4 bytes come from the retailOS allocator (veneer 0x080769b8 ->
//!   allocator @ 0x080eb67c with flag 0). Either way the ROM is asked to
//!   define a semaphore with initial count 1 into the cell
//!   (ROM 0x22003d70 via osos veneer 0x08037e70), which writes the kernel
//!   semaphore handle into *cell.
//! - `mutex_lock` — original: `FUN_0807f5c4` @ 0x0807f5c4 (8 bytes: loads
//!   the cell and tail-branches to the guard thunk @ 0x8056510). If the
//!   cell and *cell (the ROM handle) are both nonzero, waits on the
//!   semaphore (ROM 0x22003fd0 via veneer 0x08037e08).
//! - `mutex_unlock` — original: `FUN_0807f6a0` @ 0x0807f6a0 (8 bytes;
//!   tail thunk @ 0x8056710). Same guards, signals the semaphore
//!   (ROM 0x220042b4 via veneer 0x08037e10).
//! - `mutex_delete` — original: `FUN_0807f650` @ 0x0807f650 (32 bytes).
//!   If the cell is non-NULL it runs the cell-destroy thunk @ 0x805646c
//!   (guards cell/*cell, deletes the ROM semaphore with kind 1 via
//!   ROM 0x22003dc8 / veneer 0x08037e40, zeroes *cell, and frees the cell
//!   unless it is the static early-boot cell — free veneer 0x080f151c ->
//!   retailOS free @ 0x080e7970 with flag 0), then NULLs the mutex's cell
//!   pointer.
//! - `mutex_delete_counted` — original: `FUN_08094424` @ 0x08094424
//!   (40 bytes; 6 call sites). Counted-lock teardown: if the cell pointer
//!   is non-NULL the cell is destroyed by the same cell-destroy thunk
//!   @ 0x805646c `mutex_delete` uses, then all three words (cell pointer,
//!   padding, hold counter) are zeroed — the whole object returns to its
//!   born state, even when there was no cell to destroy.
//! - `kernel_running` — original: `FUN_0809444c` @ 0x0809444c (72 bytes;
//!   20 call sites). If the kernel-started byte @ 0x089ca848 is zero,
//!   returns 0. Otherwise returns the current task id (thunk @ 0x805665c:
//!   the current task's word at +8, or 0 when there is no task). If the
//!   id is 0 but a current task exists (thunk @ 0x80565f0), it first
//!   pings the task-notify helper @ 0x8060f80 with the callback pointer
//!   0x083e2e38 and then re-reads the id.
//!
//! There is NO recursive/owner/nesting state: the word at +4 is written 0
//! by create and never read anywhere — alignment padding. These "mutexes"
//! are plain RTXC counting semaphores created with count 1, so unlocking
//! an unlocked mutex simply signals the semaphore.
//!
//! Dispatch design (deviation, by necessity — mirrors the `HEAP_OPS`
//! pattern in runtime/malloc_rt.rs): the four ROM semaphore primitives
//! and the not-yet-ported RAM-side callees (heap flag/alloc/free,
//! current-task helpers, task-notify) dispatch indirectly through the
//! `ROM_KERNEL` fn-pointer table instead of undefined `extern "C"`
//! symbols that would break the freestanding ARM link while those ports
//! land in kernel/thunks.rs and the heap modules. sync_sem.rs (a
//! concurrent port) uses the same pattern with its own table; the tables
//! are meant to be unified when the kernel modules get wired together.
//! Default stubs: the ROM ops, free and notify are harmless no-ops,
//! `heap_early_flag` reports "early boot" (1) so cell creation takes the
//! static-cell path, and `heap_alloc` spins (it cannot produce memory).
//! On real hardware the table must be installed before any mutex is
//! created.
//!
//! Simplifications:
//! - The guard thunks (0x8056510 / 0x8056710 / 0x805646c) and the
//!   cell-create thunk (0x8056724) are inlined into the ported functions;
//!   guard order and NULL/zero semantics are instruction-faithful.
//! - The single shared early-boot cell (0x089cc8f8) is modeled by
//!   `EARLY_SEM_CELL`; as in the original, every pre-heap mutex aliases
//!   the same cell.
//! - Like the originals, none of the mutex functions NULL-check the
//!   `mutex` argument itself.

/// RAM-side mutex object: 8 bytes, matching the original layout.
/// `sem_cell` points at a 4-byte cell holding the ROM semaphore handle;
/// `unused` (+4) is zeroed by create and never read.
#[repr(C)]
pub struct Mutex {
    pub sem_cell: *mut u32,
    pub unused: u32,
}

/// Original: shared 4-byte semaphore cell @ 0x089cc8f8, used for every
/// mutex created while the heap "early boot" flag is nonzero.
pub static mut EARLY_SEM_CELL: u32 = 0;

/// Original: byte global @ 0x089ca848 — zero until the kernel has
/// started; gates every `kernel_running` query.
pub static mut KERNEL_STARTED: u8 = 0;

/// Original: code pointer 0x083e2e38 — callback handed to the
/// task-notify helper @ 0x08060f80 when the current task has no id yet.
/// In osos it reaches `kernel_running` as a link-time constant (literal
/// pool), not as a loaded global; modeled as a static so the value is
/// observable/overridable and matches the "globals at original
/// addresses" convention for this query.
pub static mut KERNEL_NOTIFY_CALLBACK: usize = 0x083e2e38;

/// Indirect dispatch table for the ROM kernel primitives and the
/// not-yet-ported RAM-side callees (see the module header for the design
/// and the default-stub behavior).
#[derive(Clone, Copy)]
pub struct RomKernelOps {
    /// ROM semaphore define @ 0x22003d70 (osos veneer 0x08037e70).
    /// Called with `initial_count` = 1; the ROM initializes the cell and
    /// writes the kernel semaphore handle into *cell.
    pub sema_define: unsafe extern "C" fn(initial_count: u32, cell: *mut u32),
    /// ROM semaphore wait @ 0x22003fd0 (veneer 0x08037e08); argument is
    /// the handle (*cell).
    pub sema_wait: unsafe extern "C" fn(handle: u32),
    /// ROM semaphore signal @ 0x220042b4 (veneer 0x08037e10).
    pub sema_signal: unsafe extern "C" fn(handle: u32),
    /// ROM semaphore delete @ 0x22003dc8 (veneer 0x08037e40); `kind` is
    /// always 1 in the original.
    pub sema_delete: unsafe extern "C" fn(kind: u32, cell: *mut u32),
    /// Heap "early boot" flag: `FUN_080bead8` @ 0x080bead8 (byte at
    /// heap_ctx+0xb5). Nonzero selects the shared static cell.
    pub heap_early_flag: unsafe extern "C" fn() -> u32,
    /// retailOS allocator: veneer 0x080769b8 -> 0x080eb67c (flag 0);
    /// always called with size 4 here. Ported as `os_malloc`
    /// (kernel/os_heap.rs).
    pub heap_alloc: unsafe extern "C" fn(size: usize) -> *mut u8,
    /// retailOS free: veneer 0x080f151c -> 0x080e7970 (flag 0). Ported as
    /// `os_free` (kernel/os_heap.rs).
    pub heap_free: unsafe extern "C" fn(ptr: *mut u8),
    /// Current-task query: thunk @ 0x80565f0 (NULL when no task).
    pub current_task: unsafe extern "C" fn() -> *const u32,
    /// Current-task id: thunk @ 0x805665c (task word at +8, 0 if none).
    pub current_task_id: unsafe extern "C" fn() -> i32,
    /// Task-notify helper @ 0x8060f80; argument is the callback pointer
    /// (`KERNEL_NOTIFY_CALLBACK`, 0x083e2e38 in osos).
    pub task_notify: unsafe extern "C" fn(callback: usize) -> i32,
}

// Default stubs: without the ROM/kernel these operations have no meaning.
// The no-op semaphore ops leave *cell at 0, which makes lock/unlock/delete
// safe no-ops through the NULL/zero guards. On real hardware ROM_KERNEL
// must be installed before any mutex is touched.
unsafe extern "C" fn missing_sema_define(_initial_count: u32, _cell: *mut u32) {}
unsafe extern "C" fn missing_sema_wait(_handle: u32) {}
unsafe extern "C" fn missing_sema_signal(_handle: u32) {}
unsafe extern "C" fn missing_sema_delete(_kind: u32, _cell: *mut u32) {}

/// Default stub: report "early boot" so cell creation uses the static
/// cell — the heap cannot serve allocations before it exists.
unsafe extern "C" fn missing_heap_early_flag() -> u32 {
    1
}

/// Default stub: allocation is impossible without a heap — spin (on real
/// hardware the hook must be installed before first use).
unsafe extern "C" fn missing_heap_alloc(_size: usize) -> *mut u8 {
    loop {}
}

/// Default stub: freeing into a nonexistent heap leaks the cell — a
/// harmless no-op.
unsafe extern "C" fn missing_heap_free(_ptr: *mut u8) {}

unsafe extern "C" fn missing_current_task() -> *const u32 {
    core::ptr::null()
}
unsafe extern "C" fn missing_current_task_id() -> i32 {
    0
}
unsafe extern "C" fn missing_task_notify(_callback: usize) -> i32 {
    0
}

/// The active kernel/ROM dispatch table. Defaults to the documented
/// stubs above; replaced by host tests (mocks) and eventually by the
/// ported kernel layer. Written once at init on target; tests serialize
/// access.
pub static mut ROM_KERNEL: RomKernelOps = RomKernelOps {
    sema_define: missing_sema_define,
    sema_wait: missing_sema_wait,
    sema_signal: missing_sema_signal,
    sema_delete: missing_sema_delete,
    heap_early_flag: missing_heap_early_flag,
    heap_alloc: missing_heap_alloc,
    heap_free: missing_heap_free,
    current_task: missing_current_task,
    current_task_id: missing_current_task_id,
    task_notify: missing_task_notify,
};

/// Reads the ops table. The read is volatile: the table is meant to be
/// swapped at runtime, and in a build where nothing writes it yet LLVM
/// would otherwise constant-fold the loads to the default stubs
/// (observed in malloc_rt: indirect calls collapsed to the stubs).
#[inline(always)]
fn rom_kernel() -> RomKernelOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ROM_KERNEL)) }
}

/// mutex_create — original: `FUN_080744a4` @ 0x080744a4 (28 bytes).
///
/// Creates the semaphore cell and zeroes the padding word. The `mutex`
/// argument is not NULL-checked, as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_create(mutex: *mut Mutex) {
    (*mutex).sem_cell = semaphore_cell_create();
    (*mutex).unused = 0;
}

/// Cell-create thunk @ 0x8056724, inlined: static cell while the heap is
/// in early boot, otherwise a 4-byte heap allocation; the ROM define
/// fills *cell with the semaphore handle either way.
unsafe fn semaphore_cell_create() -> *mut u32 {
    let ops = rom_kernel();
    let cell = if (ops.heap_early_flag)() != 0 {
        core::ptr::addr_of_mut!(EARLY_SEM_CELL)
    } else {
        (ops.heap_alloc)(4) as *mut u32
    };
    (ops.sema_define)(1, cell);
    cell
}

/// mutex_lock — original: `FUN_0807f5c4` @ 0x0807f5c4 (8 bytes), with
/// the guard thunk @ 0x8056510 inlined: only a live ROM handle (cell and
/// *cell both nonzero) reaches the ROM wait.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_lock(mutex: *mut Mutex) {
    let cell = (*mutex).sem_cell;
    if !cell.is_null() {
        let handle = *cell;
        if handle != 0 {
            (rom_kernel().sema_wait)(handle);
        }
    }
}

/// mutex_unlock — original: `FUN_0807f6a0` @ 0x0807f6a0 (8 bytes), with
/// the guard thunk @ 0x8056710 inlined. The mutexes are non-recursive
/// counting semaphores: unlocking an unlocked mutex just signals.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_unlock(mutex: *mut Mutex) {
    let cell = (*mutex).sem_cell;
    if !cell.is_null() {
        let handle = *cell;
        if handle != 0 {
            (rom_kernel().sema_signal)(handle);
        }
    }
}

/// mutex_delete — original: `FUN_0807f650` @ 0x0807f650 (32 bytes).
/// Destroys the cell if present, then NULLs the mutex's cell pointer.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_delete(mutex: *mut Mutex) {
    let cell = (*mutex).sem_cell;
    if !cell.is_null() {
        semaphore_cell_destroy(cell);
    }
    (*mutex).sem_cell = core::ptr::null_mut();
}

/// Cell-destroy thunk @ 0x805646c, inlined: deletes the ROM semaphore,
/// zeroes *cell, and frees the cell unless it is the shared static
/// early-boot cell.
unsafe fn semaphore_cell_destroy(cell: *mut u32) {
    if cell.is_null() || *cell == 0 {
        return;
    }
    let ops = rom_kernel();
    (ops.sema_delete)(1, cell);
    *cell = 0;
    if cell != core::ptr::addr_of_mut!(EARLY_SEM_CELL) {
        (ops.heap_free)(cell as *mut u8);
    }
}

/// kernel_running — original: `FUN_0809444c` @ 0x0809444c (72 bytes).
///
/// Returns 0 before the kernel starts (flag byte @ 0x089ca848, modeled
/// by `KERNEL_STARTED`). Once started, returns the current task id; if
/// the id is 0 but a current task exists, the task-notify helper is
/// pinged with `KERNEL_NOTIFY_CALLBACK` first and the id re-read.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kernel_running() -> i32 {
    let mut task_id = 0;
    // Volatile: nothing in this crate writes the flag yet, and LLVM
    // would otherwise fold the load to the initializer and return 0.
    if core::ptr::addr_of!(KERNEL_STARTED).read_volatile() != 0 {
        let ops = rom_kernel();
        task_id = (ops.current_task_id)();
        if task_id == 0 && !(ops.current_task)().is_null() {
            (ops.task_notify)(core::ptr::addr_of!(KERNEL_NOTIFY_CALLBACK).read_volatile());
            task_id = (ops.current_task_id)();
        }
    }
    task_id
}

/// A [`Mutex`] with a hold counter bolted on at +8 — the object the
/// counted lock pair below operates on.
///
/// Word 0 is the semaphore cell (identical to `Mutex`, and reached by the
/// same `ldr r0, [r0]` + guard chain), word 1 is the padding `mutex_create`
/// zeroes, and word 2 is the counter `mutex_lock_counted` bumps while the
/// lock is held. The originals only ever see this object as a global (e.g.
/// 0x08a79c68, used by `FUN_08124cec` / `FUN_08124d68` / `FUN_08124f7c` /
/// `FUN_08124fe8` and nothing else), never through `mutex_create` — its
/// cell is installed elsewhere.
///
/// Layout is expressed as a `repr(C)` struct rather than hand-computed byte
/// offsets so the fields stay disjoint on a 64-bit test host; on the 32-bit
/// target the offsets are exactly 0x0 / 0x4 / 0x8.
#[repr(C)]
pub struct CountedMutex {
    /// The embedded mutex: `sem_cell` at +0, padding at +4.
    pub mutex: Mutex,
    /// Hold counter at +8: incremented after acquiring, decremented
    /// before releasing.
    pub hold_count: u32,
}

/// mutex_lock_counted — original: `FUN_08094404` @ 0x08094404 (32 bytes;
/// 77 `bl` + 2 tail `b` call sites, binary-scanned).
///
/// Waits on the mutex, then increments the hold counter at +8. The
/// original open-codes `mutex_lock`'s two instructions (`ldr r0, [r0]`
/// then the guard thunk @ 0x8056510) rather than calling it; the port
/// calls the ported `mutex_lock`, which has exactly that body.
///
/// The counter does **not** gate the wait — the lock is not re-entrant,
/// and a second acquire on the same task blocks as it would without the
/// counter. It is bookkeeping: 1 while held, 0 while free. It wraps as a
/// 32-bit value, exactly like the original's `add r0, r0, #1` / `str`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_lock_counted(lock: *mut CountedMutex) {
    mutex_lock(core::ptr::addr_of_mut!((*lock).mutex));
    let count = core::ptr::addr_of_mut!((*lock).hold_count);
    count.write(count.read().wrapping_add(1));
}

/// mutex_unlock_counted — original: `FUN_0809449c` @ 0x0809449c (20 bytes;
/// 147 `bl` + 16 tail `b` call sites, binary-scanned — the most-called
/// unclaimed function in 0x08060000..0x08100000).
///
/// Decrements the hold counter at +8, then signals the mutex. The original
/// tail-branches into the guard thunk @ 0x8056710 after the store, so the
/// decrement is observably ordered *before* the release — preserved here.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_unlock_counted(lock: *mut CountedMutex) {
    let count = core::ptr::addr_of_mut!((*lock).hold_count);
    count.write(count.read().wrapping_sub(1));
    mutex_unlock(core::ptr::addr_of_mut!((*lock).mutex));
}

/// mutex_delete_counted — original: `FUN_08094424` @ 0x08094424 (40 bytes;
/// 6 `bl` call sites, binary-scanned).
///
/// Teardown for a [`CountedMutex`]: if the semaphore cell pointer (word 0)
/// is non-NULL, the cell is destroyed by the same cell-destroy thunk
/// @ 0x805646c that `mutex_delete` uses (ROM semaphore delete, `*cell`
/// zeroed, cell freed unless it is the shared static early-boot cell);
/// then all three words — cell pointer, padding, hold counter — are
/// zeroed unconditionally. Unlike `mutex_delete`, which only NULLs the
/// cell pointer of a live `Mutex`, this resets the whole counted-lock
/// object to its all-zero born state.
///
/// Every call site hands it an embedded 12-byte object inside a larger
/// struct (decomp callers pass `this + 0x18`, `this + 0x74`, `this +
/// 0x88`, `task - 0xc`), i.e. the destructor half of the
/// `mutex_lock_counted` / `mutex_unlock_counted` pair. The zeroing runs
/// even when the cell pointer is NULL — the counter is reset either way,
/// exactly like the original's three unconditional `str`s.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_delete_counted(lock: *mut CountedMutex) {
    let cell = (*lock).mutex.sem_cell;
    if !cell.is_null() {
        semaphore_cell_destroy(cell);
    }
    (*lock).mutex.sem_cell = core::ptr::null_mut();
    (*lock).mutex.unused = 0;
    (*lock).hold_count = 0;
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::vec;
    use std::vec::Vec;

    /// Serializes tests that swap the global ops table / mock state.
    static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Define(u32, usize),
        Wait(u32),
        Signal(u32),
        Delete(u32, usize),
        EarlyFlag,
        Alloc(usize),
        Free(usize),
        Task,
        TaskId,
        Notify(usize),
    }

    static CALLS: StdMutex<Vec<Call>> = StdMutex::new(Vec::new());

    fn record(call: Call) {
        CALLS.lock().unwrap().push(call);
    }

    fn calls() -> Vec<Call> {
        CALLS.lock().unwrap().clone()
    }

    // Mock control knobs / state.
    static mut EARLY_FLAG_RET: u32 = 0;
    static mut HEAP_BUF: [u32; 64] = [0; 64];
    static mut HEAP_OFF: usize = 0;
    static mut TASK_PTR_RET: usize = 0;
    static mut TASK_ID_SEQ: [i32; 4] = [0; 4];
    static mut TASK_ID_IDX: usize = 0;

    /// Handle the mock ROM define writes into the cell.
    const MOCK_HANDLE: u32 = 0x5EAA_0001;

    unsafe extern "C" fn mock_sema_define(initial_count: u32, cell: *mut u32) {
        record(Call::Define(initial_count, cell as usize));
        *cell = MOCK_HANDLE;
    }
    unsafe extern "C" fn mock_sema_wait(handle: u32) {
        record(Call::Wait(handle));
    }
    unsafe extern "C" fn mock_sema_signal(handle: u32) {
        record(Call::Signal(handle));
    }
    unsafe extern "C" fn mock_sema_delete(kind: u32, cell: *mut u32) {
        record(Call::Delete(kind, cell as usize));
    }
    unsafe extern "C" fn mock_early_flag() -> u32 {
        record(Call::EarlyFlag);
        EARLY_FLAG_RET
    }
    unsafe extern "C" fn mock_alloc(size: usize) -> *mut u8 {
        record(Call::Alloc(size));
        let offset = HEAP_OFF;
        HEAP_OFF += (size + 3) & !3;
        core::ptr::addr_of_mut!(HEAP_BUF).cast::<u8>().add(offset)
    }
    unsafe extern "C" fn mock_free(ptr: *mut u8) {
        record(Call::Free(ptr as usize));
    }
    unsafe extern "C" fn mock_current_task() -> *const u32 {
        record(Call::Task);
        TASK_PTR_RET as *const u32
    }
    unsafe extern "C" fn mock_current_task_id() -> i32 {
        record(Call::TaskId);
        let id = TASK_ID_SEQ[TASK_ID_IDX];
        if TASK_ID_IDX < TASK_ID_SEQ.len() - 1 {
            TASK_ID_IDX += 1;
        }
        id
    }
    unsafe extern "C" fn mock_task_notify(callback: usize) -> i32 {
        record(Call::Notify(callback));
        1
    }

    const MOCK_KERNEL: RomKernelOps = RomKernelOps {
        sema_define: mock_sema_define,
        sema_wait: mock_sema_wait,
        sema_signal: mock_sema_signal,
        sema_delete: mock_sema_delete,
        heap_early_flag: mock_early_flag,
        heap_alloc: mock_alloc,
        heap_free: mock_free,
        current_task: mock_current_task,
        current_task_id: mock_current_task_id,
        task_notify: mock_task_notify,
    };

    fn heap_base() -> usize {
        core::ptr::addr_of_mut!(HEAP_BUF) as usize
    }

    fn early_cell() -> *mut u32 {
        core::ptr::addr_of_mut!(EARLY_SEM_CELL)
    }

    /// Resets the mock state, installs the mock table, returns the lock
    /// guard that serializes table-swapping tests.
    fn mock_kernel() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap();
        CALLS.lock().unwrap().clear();
        unsafe {
            EARLY_FLAG_RET = 0;
            HEAP_OFF = 0;
            TASK_PTR_RET = 0;
            TASK_ID_SEQ = [0; 4];
            TASK_ID_IDX = 0;
            core::ptr::addr_of_mut!(KERNEL_STARTED).write_volatile(0);
            core::ptr::addr_of_mut!(EARLY_SEM_CELL).write_volatile(0);
            core::ptr::addr_of_mut!(KERNEL_NOTIFY_CALLBACK).write_volatile(0x083e2e38);
            *core::ptr::addr_of_mut!(ROM_KERNEL) = MOCK_KERNEL;
        }
        guard
    }

    #[test]
    fn create_heap_path_defines_semaphore() {
        let _lock = mock_kernel();
        let mut m = Mutex {
            sem_cell: 0xdead_beef as *mut u32,
            unused: 0xdead_beef,
        };
        unsafe { mutex_create(&mut m) };
        assert_eq!(m.sem_cell as usize, heap_base(), "cell must come from the heap");
        assert_eq!(m.unused, 0, "word at +4 is zeroed");
        assert_eq!(
            calls(),
            vec![
                Call::EarlyFlag,
                Call::Alloc(4),
                Call::Define(1, heap_base()),
            ]
        );
        assert_eq!(unsafe { *m.sem_cell }, MOCK_HANDLE, "ROM define fills the cell");
    }

    #[test]
    fn create_early_boot_uses_static_cell() {
        let _lock = mock_kernel();
        unsafe { EARLY_FLAG_RET = 1 };
        let mut m = Mutex {
            sem_cell: core::ptr::null_mut(),
            unused: 7,
        };
        unsafe { mutex_create(&mut m) };
        assert_eq!(m.sem_cell, early_cell());
        assert_eq!(m.unused, 0);
        assert_eq!(
            calls(),
            vec![Call::EarlyFlag, Call::Define(1, early_cell() as usize)],
            "no heap allocation on the early-boot path"
        );
    }

    #[test]
    fn lock_unlock_pairing() {
        let _lock = mock_kernel();
        let mut cell: u32 = 0x42;
        let mut m = Mutex {
            sem_cell: &mut cell,
            unused: 0,
        };
        unsafe {
            mutex_lock(&mut m);
            mutex_unlock(&mut m);
        }
        assert_eq!(calls(), vec![Call::Wait(0x42), Call::Signal(0x42)]);
    }

    #[test]
    fn lock_unlock_null_cell_is_noop() {
        let _lock = mock_kernel();
        let mut m = Mutex {
            sem_cell: core::ptr::null_mut(),
            unused: 0,
        };
        unsafe {
            mutex_lock(&mut m);
            mutex_unlock(&mut m);
        }
        assert_eq!(calls(), vec![], "NULL cell must not reach the ROM");
    }

    #[test]
    fn lock_unlock_zero_handle_is_noop() {
        let _lock = mock_kernel();
        let mut cell: u32 = 0;
        let mut m = Mutex {
            sem_cell: &mut cell,
            unused: 0,
        };
        unsafe {
            mutex_lock(&mut m);
            mutex_unlock(&mut m);
        }
        assert_eq!(calls(), vec![], "zero ROM handle must not reach the ROM");
    }

    #[test]
    fn unlock_when_unlocked_just_signals() {
        let _lock = mock_kernel();
        let mut cell: u32 = 0x99;
        let mut m = Mutex {
            sem_cell: &mut cell,
            unused: 0,
        };
        unsafe {
            // No owner/nesting state: unlock signals the semaphore even
            // without a preceding lock, and twice in a row.
            mutex_unlock(&mut m);
            mutex_unlock(&mut m);
        }
        assert_eq!(calls(), vec![Call::Signal(0x99), Call::Signal(0x99)]);
    }

    #[test]
    fn delete_heap_cell_deletes_and_frees() {
        let _lock = mock_kernel();
        let mut m = Mutex {
            sem_cell: core::ptr::null_mut(),
            unused: 0,
        };
        unsafe { mutex_create(&mut m) };
        CALLS.lock().unwrap().clear();
        let cell = m.sem_cell;
        unsafe { mutex_delete(&mut m) };
        assert_eq!(
            calls(),
            vec![Call::Delete(1, cell as usize), Call::Free(cell as usize)]
        );
        assert_eq!(unsafe { *cell }, 0, "cell is zeroed after delete");
        assert!(m.sem_cell.is_null(), "mutex cell pointer is NULLed");
    }

    #[test]
    fn delete_early_cell_is_not_freed() {
        let _lock = mock_kernel();
        unsafe { EARLY_FLAG_RET = 1 };
        let mut m = Mutex {
            sem_cell: core::ptr::null_mut(),
            unused: 0,
        };
        unsafe { mutex_create(&mut m) };
        CALLS.lock().unwrap().clear();
        unsafe { mutex_delete(&mut m) };
        assert_eq!(
            calls(),
            vec![Call::Delete(1, early_cell() as usize)],
            "the shared static cell must not be freed"
        );
        assert_eq!(unsafe { *early_cell() }, 0);
        assert!(m.sem_cell.is_null());
    }

    #[test]
    fn delete_null_sem_is_noop() {
        let _lock = mock_kernel();
        let mut m = Mutex {
            sem_cell: core::ptr::null_mut(),
            unused: 0,
        };
        unsafe { mutex_delete(&mut m) };
        assert_eq!(calls(), vec![]);
        assert!(m.sem_cell.is_null());
    }

    #[test]
    fn delete_zero_handle_skips_rom_but_nulls() {
        let _lock = mock_kernel();
        let mut cell: u32 = 0;
        let mut m = Mutex {
            sem_cell: &mut cell,
            unused: 0,
        };
        unsafe { mutex_delete(&mut m) };
        assert_eq!(calls(), vec![], "zero handle: no ROM delete, no free");
        assert!(m.sem_cell.is_null());
    }

    #[test]
    fn kernel_running_not_started() {
        let _lock = mock_kernel();
        assert_eq!(unsafe { kernel_running() }, 0);
        assert_eq!(calls(), vec![], "flag 0: no kernel queries at all");
    }

    #[test]
    fn kernel_running_returns_task_id() {
        let _lock = mock_kernel();
        unsafe {
            core::ptr::addr_of_mut!(KERNEL_STARTED).write_volatile(1);
            TASK_ID_SEQ = [7, 7, 7, 7];
        }
        assert_eq!(unsafe { kernel_running() }, 7);
        assert_eq!(calls(), vec![Call::TaskId], "nonzero id: no notify");
    }

    #[test]
    fn kernel_running_id_zero_no_task() {
        let _lock = mock_kernel();
        unsafe {
            core::ptr::addr_of_mut!(KERNEL_STARTED).write_volatile(1);
            TASK_ID_SEQ = [0; 4];
            TASK_PTR_RET = 0;
        }
        assert_eq!(unsafe { kernel_running() }, 0);
        assert_eq!(
            calls(),
            vec![Call::TaskId, Call::Task],
            "NULL current task: no notify"
        );
    }

    #[test]
    fn kernel_running_id_zero_with_task_notifies() {
        let _lock = mock_kernel();
        unsafe {
            core::ptr::addr_of_mut!(KERNEL_STARTED).write_volatile(1);
            TASK_ID_SEQ = [0, 3, 3, 3];
            TASK_PTR_RET = 0x08AC_5CCC;
        }
        assert_eq!(unsafe { kernel_running() }, 3);
        assert_eq!(
            calls(),
            vec![
                Call::TaskId,
                Call::Task,
                Call::Notify(0x083e2e38),
                Call::TaskId,
            ]
        );
    }

    // -- the counted lock pair @ 0x08094404 / 0x0809449c ------------------

    /// A live counted lock: cell holds `MOCK_HANDLE`, so ROM ops fire.
    fn live_counted_lock(cell: *mut u32, hold_count: u32) -> CountedMutex {
        CountedMutex {
            mutex: Mutex { sem_cell: cell, unused: 0 },
            hold_count,
        }
    }

    #[test]
    fn counted_lock_waits_then_increments() {
        let _lock = mock_kernel();
        let mut cell = MOCK_HANDLE;
        let mut lock = live_counted_lock(&mut cell, 0);
        unsafe { mutex_lock_counted(&mut lock) };
        assert_eq!(calls(), vec![Call::Wait(MOCK_HANDLE)]);
        assert_eq!(lock.hold_count, 1, "held");
    }

    #[test]
    fn counted_unlock_decrements_then_signals() {
        let _lock = mock_kernel();
        let mut cell = MOCK_HANDLE;
        let mut lock = live_counted_lock(&mut cell, 1);
        unsafe { mutex_unlock_counted(&mut lock) };
        assert_eq!(calls(), vec![Call::Signal(MOCK_HANDLE)]);
        assert_eq!(lock.hold_count, 0, "released");
    }

    /// Acquire/release around a critical section leaves the counter where
    /// it started and issues exactly one wait and one signal.
    #[test]
    fn counted_pair_round_trips() {
        let _lock = mock_kernel();
        let mut cell = MOCK_HANDLE;
        let mut lock = live_counted_lock(&mut cell, 0);
        unsafe {
            mutex_lock_counted(&mut lock);
            assert_eq!(lock.hold_count, 1);
            mutex_unlock_counted(&mut lock);
        }
        assert_eq!(lock.hold_count, 0);
        assert_eq!(calls(), vec![Call::Wait(MOCK_HANDLE), Call::Signal(MOCK_HANDLE)]);
    }

    /// The counter is bookkeeping, not a gate: nested acquires each take
    /// the semaphore and each bump the count (the lock is NOT re-entrant).
    #[test]
    fn counted_lock_does_not_short_circuit_on_a_held_lock() {
        let _lock = mock_kernel();
        let mut cell = MOCK_HANDLE;
        let mut lock = live_counted_lock(&mut cell, 0);
        unsafe {
            mutex_lock_counted(&mut lock);
            mutex_lock_counted(&mut lock);
        }
        assert_eq!(lock.hold_count, 2);
        assert_eq!(
            calls(),
            vec![Call::Wait(MOCK_HANDLE), Call::Wait(MOCK_HANDLE)],
            "second acquire still waits"
        );
    }

    /// The guards are inherited from `mutex_lock`/`mutex_unlock`: a NULL
    /// cell or a zero handle reaches no ROM op — but the counter still
    /// moves, exactly as in the original (the add/sub are unconditional).
    #[test]
    fn counted_pair_moves_the_counter_even_when_guarded_off() {
        let _lock = mock_kernel();
        let mut dead_handle = 0u32;
        for cell in [core::ptr::null_mut(), &mut dead_handle as *mut u32] {
            let mut lock = live_counted_lock(cell, 5);
            unsafe {
                mutex_lock_counted(&mut lock);
                assert_eq!(lock.hold_count, 6, "increment is unconditional");
                mutex_unlock_counted(&mut lock);
                assert_eq!(lock.hold_count, 5, "decrement is unconditional");
            }
        }
        assert_eq!(calls(), vec![], "no ROM op behind the guards");
    }

    /// 32-bit wrap, matching the original's bare `add`/`sub` and `str`.
    #[test]
    fn counted_pair_wraps_as_32_bit() {
        let _lock = mock_kernel();
        let mut cell = MOCK_HANDLE;
        let mut underflow = live_counted_lock(&mut cell, 0);
        unsafe { mutex_unlock_counted(&mut underflow) };
        assert_eq!(underflow.hold_count, u32::MAX, "unlock of a free lock wraps");
        let mut overflow = live_counted_lock(&mut cell, u32::MAX);
        unsafe { mutex_lock_counted(&mut overflow) };
        assert_eq!(overflow.hold_count, 0);
    }

    /// Ordering: the original stores the decremented counter *before*
    /// tail-branching into the release guard, so a signal handler that
    /// inspects the lock must already see the new value.
    #[test]
    fn counted_unlock_decrements_before_signalling() {
        let _lock = mock_kernel();
        static mut PROBED_LOCK: *const CountedMutex = core::ptr::null();
        static mut COUNT_SEEN_AT_SIGNAL: u32 = 0xffff_ffff;
        unsafe extern "C" fn probing_signal(handle: u32) {
            record(Call::Signal(handle));
            unsafe { COUNT_SEEN_AT_SIGNAL = (*PROBED_LOCK).hold_count };
        }
        let mut cell = MOCK_HANDLE;
        let mut lock = live_counted_lock(&mut cell, 3);
        unsafe {
            PROBED_LOCK = &lock;
            let mut ops = MOCK_KERNEL;
            ops.sema_signal = probing_signal;
            *core::ptr::addr_of_mut!(ROM_KERNEL) = ops;
            mutex_unlock_counted(&mut lock);
            assert_eq!(COUNT_SEEN_AT_SIGNAL, 2, "counter already decremented");
            assert_eq!(lock.hold_count, 2);
        }
        assert_eq!(calls(), vec![Call::Signal(MOCK_HANDLE)]);
    }

    // -- the counted-lock teardown @ 0x08094424 -------------------------

    /// A live heap cell is destroyed (ROM delete + free), then every word
    /// of the object is zeroed.
    #[test]
    fn delete_counted_destroys_cell_and_zeroes_all_words() {
        let _lock = mock_kernel();
        let mut m = Mutex {
            sem_cell: core::ptr::null_mut(),
            unused: 0,
        };
        unsafe { mutex_create(&mut m) };
        CALLS.lock().unwrap().clear();
        let cell = m.sem_cell;
        let mut lock = CountedMutex {
            mutex: m,
            hold_count: 9,
        };
        unsafe { mutex_delete_counted(&mut lock) };
        assert_eq!(
            calls(),
            vec![Call::Delete(1, cell as usize), Call::Free(cell as usize)]
        );
        assert_eq!(unsafe { *cell }, 0, "cell is zeroed after delete");
        assert!(lock.mutex.sem_cell.is_null(), "cell pointer NULLed");
        assert_eq!(lock.mutex.unused, 0, "padding zeroed");
        assert_eq!(lock.hold_count, 0, "hold counter reset");
    }

    /// NULL cell: no ROM op, no free — but the object is still zeroed,
    /// counter included (the three stores are unconditional).
    #[test]
    fn delete_counted_null_cell_still_resets_the_object() {
        let _lock = mock_kernel();
        let mut lock = CountedMutex {
            mutex: Mutex {
                sem_cell: core::ptr::null_mut(),
                unused: 0xdead_beef,
            },
            hold_count: 0xdead_beef,
        };
        unsafe { mutex_delete_counted(&mut lock) };
        assert_eq!(calls(), vec![]);
        assert!(lock.mutex.sem_cell.is_null());
        assert_eq!(lock.mutex.unused, 0);
        assert_eq!(lock.hold_count, 0);
    }

    /// A zero ROM handle guards off the thunk's ROM delete and free, but
    /// the object is still fully reset.
    #[test]
    fn delete_counted_zero_handle_resets_without_rom() {
        let _lock = mock_kernel();
        let mut cell: u32 = 0;
        let mut lock = live_counted_lock(&mut cell, 4);
        unsafe { mutex_delete_counted(&mut lock) };
        assert_eq!(calls(), vec![], "zero handle: no ROM delete, no free");
        assert!(lock.mutex.sem_cell.is_null());
        assert_eq!(lock.hold_count, 0);
    }

    /// The shared early-boot cell is deleted but never freed, same as
    /// `mutex_delete`; the object around it is still zeroed.
    #[test]
    fn delete_counted_early_cell_is_not_freed() {
        let _lock = mock_kernel();
        unsafe { EARLY_FLAG_RET = 1 };
        let mut m = Mutex {
            sem_cell: core::ptr::null_mut(),
            unused: 0,
        };
        unsafe { mutex_create(&mut m) };
        CALLS.lock().unwrap().clear();
        let mut lock = CountedMutex {
            mutex: m,
            hold_count: 2,
        };
        unsafe { mutex_delete_counted(&mut lock) };
        assert_eq!(
            calls(),
            vec![Call::Delete(1, early_cell() as usize)],
            "the shared static cell must not be freed"
        );
        assert_eq!(unsafe { *early_cell() }, 0);
        assert!(lock.mutex.sem_cell.is_null());
        assert_eq!(lock.hold_count, 0);
    }
}

//! Ports of the RAM-side RTXC Quadros semaphore wrappers. The RTXC kernel
//! itself lives in the S5L8702 mask ROM at 0x22000000 and is reached through
//! single-instruction `ldr pc, [pc, #-4]` thunks in osos (0x08037db0..).
//!
//! - `sem_create` — original: `FUN_08056724` @ 0x08056724 (52 bytes). If the
//!   ISR/system-context check (`FUN_080bead8`, reads the byte at
//!   *0x089ca638 + 0xb5) is nonzero, the handle slot is the fixed static at
//!   0x089cc8f8 (no allocation allowed in ISR context); otherwise 4 bytes
//!   come from the retailOS heap via the alloc wrapper @ 0x080769b8. It then
//!   calls the ROM create dispatcher through thunk 0x08037e70 -> ROM
//!   0x22003d70 with r0 = opcode 1 (semaphore) and r1 = slot, and returns
//!   the slot. The heap result is NOT checked: a failed allocation forwards
//!   NULL into the dispatcher and to the caller.
//! - `sem_delete` — original: `FUN_0805646c` @ 0x0805646c (68 bytes). NULL
//!   slot or NULL `*slot` is a silent no-op. Otherwise it calls the ROM
//!   delete dispatcher through thunk 0x08037e40 -> ROM 0x22003dc8 with
//!   r0 = opcode 1 (semaphore) and r1 = slot, clears `*slot`, and — unless
//!   the slot is the fixed ISR static — tail-branches to the retailOS free
//!   veneer @ 0x080f151c (free @ 0x080e7970 with flag r1 = 0).
//! - `sem_wait` — original: `FUN_08056510` @ 0x08056510 (20 bytes). NULL
//!   slot or NULL `*slot` returns immediately; otherwise tail-branches
//!   through thunk 0x08037e08 -> ROM 0x22003fd0 with r0 = `*slot` (the
//!   kernel semaphore ID). 14 call sites in osos.
//! - `sem_signal` — original: `FUN_08056710` @ 0x08056710 (20 bytes). Same
//!   guard; tail-branches through thunk 0x08037e10 -> ROM 0x220042b4 with
//!   r0 = `*slot`. 11 call sites in osos.
//!
//! A semaphore handle in RAM is a pointer to a 4-byte slot; the ROM create
//! dispatcher writes the kernel semaphore ID into the slot, delete clears
//! it, and wait/signal pass the ID itself to the ROM. The wrappers keep no
//! other RAM-side bookkeeping — no state structs, no error codes (the
//! originals return the raw slot pointer or void and never fail loudly).
//!
//! ROM-dispatch design (deviation, by necessity): the ROM kernel functions
//! (0x22003d70 / 0x22003dc8 / 0x22003fd0 / 0x220042b4) are not in osos, and
//! the RAM-side helpers they lean on — the ISR-context check @ 0x080bead8,
//! the heap alloc wrapper @ 0x080769b8, the free veneer @ 0x080f151c — are
//! not yet ported. Instead of undefined `extern "C"` symbols (which would
//! break the freestanding ARM link) all seven entry points dispatch
//! indirectly through the `ROM_KERNEL` function-pointer table. The table
//! defaults to documented stubs (see each `missing_*`); on real hardware it
//! must be installed before semaphores are touched. Host tests swap in a
//! mock kernel.
//!
//! Further simplifications/deviations:
//! - The ISR-context static slot (0x089cc8f8) lives in osos's RAM image, so
//!   the port substitutes a crate-local `static mut ISR_SEM_SLOT`; the
//!   semantics (one shared, never-freed slot for ISR-context semaphores)
//!   are preserved, and `sem_delete`'s "don't free the static" check
//!   compares against it.
//! - Note on opcodes: create and delete use DIFFERENT ROM dispatchers
//!   (create 0x22003d70, delete 0x22003dc8) but the same opcode r0 = 1 =
//!   semaphore. Neighboring wrappers pass opcode 2 through the same
//!   dispatchers for an 8-byte kernel object (FUN_0805675c/FUN_080564b0,
//!   likely mailboxes), which is why the dispatchers take an opcode at all.
//! - The ROM wait/signal stubs spin / no-op respectively: a wait that
//!   silently succeeded would hide a missing table install behind data
//!   races, while blocking forever (like waiting on a never-signaled
//!   semaphore) surfaces it.
//! - Symbol exports (`#[no_mangle]`) are gated to the firmware target (`target_os = "none"`):
//!   `sem_wait` collides with the POSIX `sem_wait` in libSystem, and on
//!   macOS dyld would interpose the test executable's export over the
//!   system one (same failure mode as malloc/free in malloc_rt.rs).

/// RAM semaphore handle: pointer to the 4-byte slot holding the ROM
/// kernel's semaphore ID (written by create, cleared by delete).
pub type SemHandle = *mut u32;

/// Dispatcher opcode for semaphores — r0 = 1 in both the ROM create
/// dispatcher (0x22003d70) and the ROM delete dispatcher (0x22003dc8).
const SEM_OP: u32 = 1;

/// Stand-in for the original's fixed ISR-context handle slot @ 0x089cc8f8
/// (see the module header). Never heap-allocated, never freed.
static mut ISR_SEM_SLOT: u32 = 0;

/// Indirect dispatch table for the mask-ROM kernel ops and the not-yet-
/// ported RAM helpers (see the module header for the design and stubs).
#[derive(Clone, Copy)]
pub struct RomKernel {
    /// ROM create dispatcher @ 0x22003d70 (via thunk 0x08037e70). Called
    /// with (opcode, slot); opcode 1 = semaphore. Writes the kernel
    /// semaphore ID into `*slot`.
    pub op_create: unsafe extern "C" fn(op: u32, slot: SemHandle),
    /// ROM delete dispatcher @ 0x22003dc8 (via thunk 0x08037e40). Called
    /// with (opcode, slot); opcode 1 = semaphore.
    pub op_delete: unsafe extern "C" fn(op: u32, slot: SemHandle),
    /// ROM semaphore wait @ 0x22003fd0 (via thunk 0x08037e08). Takes the
    /// kernel semaphore ID (`*slot`), blocks until signaled.
    pub wait: unsafe extern "C" fn(sem: u32),
    /// ROM semaphore signal @ 0x220042b4 (via thunk 0x08037e10). Takes the
    /// kernel semaphore ID (`*slot`).
    pub signal: unsafe extern "C" fn(sem: u32),
    /// RAM helper @ 0x080bead8: nonzero when running in ISR/system context
    /// (reads the byte at *0x089ca638 + 0xb5). Not yet ported.
    pub in_isr_context: unsafe extern "C" fn() -> u32,
    /// RAM heap-alloc wrapper @ 0x080769b8 (retailOS heap). `sem_create`
    /// allocates the 4-byte handle slot through it. Not yet ported.
    pub heap_alloc: unsafe extern "C" fn(size: usize) -> SemHandle,
    /// RAM free veneer @ 0x080f151c (retailOS free @ 0x080e7970, flag 0).
    /// Not yet ported.
    pub heap_free: unsafe extern "C" fn(ptr: SemHandle),
}

/// Default stub: without the ROM kernel no semaphore can be created — spin.
/// On real hardware `ROM_KERNEL` must be installed before use.
unsafe extern "C" fn missing_op_create(_op: u32, _slot: SemHandle) {
    loop {}
}

/// Default stub: deleting into a nonexistent kernel is a harmless no-op
/// (like `missing_free` in malloc_rt.rs).
unsafe extern "C" fn missing_op_delete(_op: u32, _slot: SemHandle) {}

/// Default stub: behave like a wait on a never-signaled semaphore — block
/// forever. Returning silently would hide a missing table install.
unsafe extern "C" fn missing_wait(_sem: u32) {
    loop {}
}

/// Default stub: signaling a nonexistent kernel is a harmless no-op.
unsafe extern "C" fn missing_signal(_sem: u32) {}

/// Default stub: assume task context (0) — matches the retailOS state byte
/// at *0x089ca638 + 0xb5 when no ISR is active.
unsafe extern "C" fn missing_in_isr_context() -> u32 {
    0
}

/// Default stub: allocation is impossible without the heap — spin (same
/// contract as `missing_alloc` in malloc_rt.rs).
unsafe extern "C" fn missing_heap_alloc(_size: usize) -> SemHandle {
    loop {}
}

/// Default stub: freeing into a nonexistent heap leaks the slot — a
/// harmless no-op.
unsafe extern "C" fn missing_heap_free(_ptr: SemHandle) {}

/// The active kernel/heap implementation. Defaults to the documented stubs
/// above; replaced by host tests (mock kernel) and eventually by the ported
/// retailOS helpers plus real ROM veneers. Written once at init on target;
/// tests serialize access.
pub static mut ROM_KERNEL: RomKernel = RomKernel {
    op_create: missing_op_create,
    op_delete: missing_op_delete,
    wait: missing_wait,
    signal: missing_signal,
    in_isr_context: missing_in_isr_context,
    heap_alloc: missing_heap_alloc,
    heap_free: missing_heap_free,
};

/// Reads the ops table. The read is volatile: the table is meant to be
/// swapped at runtime, and otherwise LLVM would constant-fold the loads to
/// the default stubs and inline their `loop {}` bodies (observed in
/// malloc_rt.rs: `malloc` collapsed to a branch-to-self in ARM release).
#[inline(always)]
fn rom_kernel() -> RomKernel {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ROM_KERNEL)) }
}

/// sem_create — original: `FUN_08056724` @ 0x08056724 (52 bytes).
///
/// Returns the handle slot: the shared ISR static when in ISR context, a
/// fresh 4-byte heap slot otherwise. The ROM create dispatcher (opcode 1)
/// fills `*slot` with the kernel semaphore ID. A failed heap allocation is
/// forwarded unchecked, exactly like the original.
// NOTE: `#[no_mangle]` is gated to the firmware target — on macOS, dyld
// interposes the test executable's exported `sem_wait` over libSystem's
// POSIX one (see the module header). ARM/release builds export normally
// for match.py and linking.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sem_create() -> SemHandle {
    let ops = rom_kernel();
    let slot = if (ops.in_isr_context)() != 0 {
        core::ptr::addr_of_mut!(ISR_SEM_SLOT)
    } else {
        (ops.heap_alloc)(4)
    };
    (ops.op_create)(SEM_OP, slot);
    slot
}

/// sem_delete — original: `FUN_0805646c` @ 0x0805646c (68 bytes).
///
/// NULL slot or NULL `*slot` is a silent no-op. Otherwise dispatches the
/// ROM delete (opcode 1), clears `*slot`, and frees the slot unless it is
/// the shared ISR static.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sem_delete(sem: SemHandle) {
    if sem.is_null() || *sem == 0 {
        return;
    }
    let ops = rom_kernel();
    (ops.op_delete)(SEM_OP, sem);
    *sem = 0;
    if sem != core::ptr::addr_of_mut!(ISR_SEM_SLOT) {
        (ops.heap_free)(sem);
    }
}

/// sem_wait — original: `FUN_08056510` @ 0x08056510 (20 bytes).
///
/// NULL slot or NULL `*slot` returns immediately; otherwise blocks in the
/// ROM wait on the kernel semaphore ID `*slot`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sem_wait(sem: SemHandle) {
    if sem.is_null() || *sem == 0 {
        return;
    }
    (rom_kernel().wait)(*sem);
}

/// sem_signal — original: `FUN_08056710` @ 0x08056710 (20 bytes).
///
/// NULL slot or NULL `*slot` returns immediately; otherwise signals the
/// kernel semaphore ID `*slot` in the ROM.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sem_signal(sem: SemHandle) {
    if sem.is_null() || *sem == 0 {
        return;
    }
    (rom_kernel().signal)(*sem);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that swap the global ops table / mock state.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    // Mock kernel call log.
    static mut CREATE_CALLS: usize = 0;
    static mut LAST_CREATE_OP: u32 = 0;
    static mut LAST_CREATE_SLOT: SemHandle = core::ptr::null_mut();
    static mut CREATE_WRITES_ID: u32 = 0;
    static mut DELETE_CALLS: usize = 0;
    static mut LAST_DELETE_OP: u32 = 0;
    static mut LAST_DELETE_SLOT: SemHandle = core::ptr::null_mut();
    static mut WAIT_CALLS: usize = 0;
    static mut LAST_WAIT_SEM: u32 = 0;
    static mut SIGNAL_CALLS: usize = 0;
    static mut LAST_SIGNAL_SEM: u32 = 0;
    static mut ISR_RET: u32 = 0;
    static mut ALLOC_CALLS: usize = 0;
    static mut LAST_ALLOC_SIZE: usize = 0;
    static mut ALLOC_RET: SemHandle = core::ptr::null_mut();
    static mut FREE_CALLS: usize = 0;
    static mut LAST_FREE_PTR: SemHandle = core::ptr::null_mut();

    /// Fake kernel semaphore ID the mock create writes into the slot.
    const KERNEL_SEM_ID: u32 = 0x5E4A_0001;

    unsafe extern "C" fn mock_op_create(op: u32, slot: SemHandle) {
        CREATE_CALLS += 1;
        LAST_CREATE_OP = op;
        LAST_CREATE_SLOT = slot;
        if !slot.is_null() {
            *slot = CREATE_WRITES_ID;
        }
    }

    unsafe extern "C" fn mock_op_delete(op: u32, slot: SemHandle) {
        DELETE_CALLS += 1;
        LAST_DELETE_OP = op;
        LAST_DELETE_SLOT = slot;
    }

    unsafe extern "C" fn mock_wait(sem: u32) {
        WAIT_CALLS += 1;
        LAST_WAIT_SEM = sem;
    }

    unsafe extern "C" fn mock_signal(sem: u32) {
        SIGNAL_CALLS += 1;
        LAST_SIGNAL_SEM = sem;
    }

    unsafe extern "C" fn mock_in_isr_context() -> u32 {
        ISR_RET
    }

    unsafe extern "C" fn mock_heap_alloc(size: usize) -> SemHandle {
        ALLOC_CALLS += 1;
        LAST_ALLOC_SIZE = size;
        ALLOC_RET
    }

    unsafe extern "C" fn mock_heap_free(ptr: SemHandle) {
        FREE_CALLS += 1;
        LAST_FREE_PTR = ptr;
    }

    const MOCK_OPS: RomKernel = RomKernel {
        op_create: mock_op_create,
        op_delete: mock_op_delete,
        wait: mock_wait,
        signal: mock_signal,
        in_isr_context: mock_in_isr_context,
        heap_alloc: mock_heap_alloc,
        heap_free: mock_heap_free,
    };

    /// Resets the mock log, installs the mock table, returns the lock guard.
    /// Default mock state: task context, create writes KERNEL_SEM_ID, heap
    /// hands out a caller-set slot.
    fn mock_kernel() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap();
        unsafe {
            CREATE_CALLS = 0;
            LAST_CREATE_OP = 0;
            LAST_CREATE_SLOT = core::ptr::null_mut();
            CREATE_WRITES_ID = KERNEL_SEM_ID;
            DELETE_CALLS = 0;
            LAST_DELETE_OP = 0;
            LAST_DELETE_SLOT = core::ptr::null_mut();
            WAIT_CALLS = 0;
            LAST_WAIT_SEM = 0;
            SIGNAL_CALLS = 0;
            LAST_SIGNAL_SEM = 0;
            ISR_RET = 0;
            ALLOC_CALLS = 0;
            LAST_ALLOC_SIZE = 0;
            ALLOC_RET = core::ptr::null_mut();
            FREE_CALLS = 0;
            LAST_FREE_PTR = core::ptr::null_mut();
            ISR_SEM_SLOT = 0;
            *core::ptr::addr_of_mut!(ROM_KERNEL) = MOCK_OPS;
        }
        guard
    }

    #[test]
    fn create_in_task_context_allocates_slot_and_dispatches_op1() {
        let _lock = mock_kernel();
        let mut backing: u32 = 0;
        unsafe {
            ALLOC_RET = &mut backing;
            let slot = sem_create();
            assert_eq!(slot, &mut backing as SemHandle);
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(LAST_ALLOC_SIZE, 4, "slot is 4 bytes");
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(LAST_CREATE_OP, 1, "create dispatcher opcode 1 = sem");
            assert_eq!(LAST_CREATE_SLOT, slot);
            assert_eq!(backing, KERNEL_SEM_ID, "ROM writes the ID into *slot");
        }
    }

    #[test]
    fn create_in_isr_context_uses_static_slot_without_alloc() {
        let _lock = mock_kernel();
        unsafe {
            ISR_RET = 1;
            let slot = sem_create();
            assert_eq!(slot, core::ptr::addr_of_mut!(ISR_SEM_SLOT));
            assert_eq!(ALLOC_CALLS, 0, "ISR context must not allocate");
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(LAST_CREATE_OP, 1);
            assert_eq!(LAST_CREATE_SLOT, slot);
        }
    }

    #[test]
    fn create_forwards_failed_allocation_unchecked() {
        let _lock = mock_kernel();
        unsafe {
            ALLOC_RET = core::ptr::null_mut(); // heap exhausted
            let slot = sem_create();
            assert!(slot.is_null(), "original returns the raw heap result");
            // The original dispatches (1, NULL) without checking.
            assert_eq!(CREATE_CALLS, 1);
            assert_eq!(LAST_CREATE_OP, 1);
            assert!(LAST_CREATE_SLOT.is_null());
        }
    }

    #[test]
    fn delete_dispatches_op1_clears_slot_and_frees() {
        let _lock = mock_kernel();
        let mut backing: u32 = KERNEL_SEM_ID;
        unsafe {
            let slot = &mut backing as SemHandle;
            sem_delete(slot);
            assert_eq!(DELETE_CALLS, 1);
            assert_eq!(LAST_DELETE_OP, 1, "delete dispatcher opcode 1 = sem");
            assert_eq!(LAST_DELETE_SLOT, slot);
            assert_eq!(backing, 0, "slot is cleared after delete");
            assert_eq!(FREE_CALLS, 1);
            assert_eq!(LAST_FREE_PTR, slot);
        }
    }

    #[test]
    fn delete_null_slot_is_silent_noop() {
        let _lock = mock_kernel();
        unsafe {
            sem_delete(core::ptr::null_mut());
            assert_eq!(DELETE_CALLS, 0);
            assert_eq!(FREE_CALLS, 0);
        }
    }

    #[test]
    fn delete_empty_slot_is_silent_noop() {
        let _lock = mock_kernel();
        let mut backing: u32 = 0; // *slot == NULL
        unsafe {
            sem_delete(&mut backing);
            assert_eq!(DELETE_CALLS, 0, "NULL *slot must not reach the ROM");
            assert_eq!(FREE_CALLS, 0, "empty slot is not freed either");
        }
    }

    #[test]
    fn delete_isr_static_slot_is_not_freed() {
        let _lock = mock_kernel();
        unsafe {
            ISR_SEM_SLOT = KERNEL_SEM_ID;
            let slot = core::ptr::addr_of_mut!(ISR_SEM_SLOT);
            sem_delete(slot);
            assert_eq!(DELETE_CALLS, 1);
            assert_eq!(LAST_DELETE_OP, 1);
            assert_eq!(LAST_DELETE_SLOT, slot);
            assert_eq!(ISR_SEM_SLOT, 0, "static slot is still cleared");
            assert_eq!(FREE_CALLS, 0, "the static slot is never freed");
        }
    }

    #[test]
    fn wait_passes_kernel_id_to_rom() {
        let _lock = mock_kernel();
        let mut backing: u32 = KERNEL_SEM_ID;
        unsafe {
            sem_wait(&mut backing);
            assert_eq!(WAIT_CALLS, 1);
            assert_eq!(LAST_WAIT_SEM, KERNEL_SEM_ID);
        }
    }

    #[test]
    fn wait_guards_null_slot_and_null_id() {
        let _lock = mock_kernel();
        let mut backing: u32 = 0;
        unsafe {
            sem_wait(core::ptr::null_mut());
            sem_wait(&mut backing);
            assert_eq!(WAIT_CALLS, 0, "guarded waits must not reach the ROM");
        }
    }

    #[test]
    fn signal_passes_kernel_id_to_rom() {
        let _lock = mock_kernel();
        let mut backing: u32 = KERNEL_SEM_ID;
        unsafe {
            sem_signal(&mut backing);
            assert_eq!(SIGNAL_CALLS, 1);
            assert_eq!(LAST_SIGNAL_SEM, KERNEL_SEM_ID);
        }
    }

    #[test]
    fn signal_guards_null_slot_and_null_id() {
        let _lock = mock_kernel();
        let mut backing: u32 = 0;
        unsafe {
            sem_signal(core::ptr::null_mut());
            sem_signal(&mut backing);
            assert_eq!(SIGNAL_CALLS, 0, "guarded signals must not reach the ROM");
        }
    }

    #[test]
    fn create_wait_signal_delete_roundtrip_through_mock_kernel() {
        let _lock = mock_kernel();
        let mut backing: u32 = 0;
        unsafe {
            ALLOC_RET = &mut backing;
            let slot = sem_create();
            assert_eq!(*slot, KERNEL_SEM_ID);
            sem_wait(slot);
            sem_signal(slot);
            sem_delete(slot);
            assert_eq!(*slot, 0);
            assert_eq!(WAIT_CALLS, 1);
            assert_eq!(SIGNAL_CALLS, 1);
            assert_eq!(DELETE_CALLS, 1);
            assert_eq!(FREE_CALLS, 1);
        }
    }
}

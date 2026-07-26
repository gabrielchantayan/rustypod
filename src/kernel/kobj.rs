//! RAM-side wrappers for the RTXC opcode-2 kernel objects — the second
//! object class of the mask-ROM create/delete dispatchers (opcode 1 =
//! semaphores, kernel/sync_sem.rs). Two usage shapes share the class:
//!
//! - A heap-resident **mailbox block** of 8 bytes ({state, id}), created by
//!   `mailbox_create` and torn down by `mailbox_delete`.
//! - A bare **waiter object id** kept in a caller-owned slot (the condvar
//!   layer's per-waiter wakeup objects, kernel/condvar.rs), created by
//!   `waiter_create` and destroyed by `waiter_delete`.
//!
//! Originals:
//!
//! - `mailbox_create` — `FUN_0805675c` @ 0x0805675c (44 bytes; 2 call
//!   sites, 0x0808e29c / 0x080e8760). `block = os_malloc(8)`;
//!   `block->state = 0`; ROM create dispatch (thunk 0x08037e70 -> ROM
//!   0x22003d70) with (opcode 2, &block->id) — the dispatcher writes the
//!   kernel object id into the slot; returns the block. The `state` word
//!   belongs to the owner and is never touched again here. The os_malloc
//!   result is NOT NULL-checked (a failed allocation faults on the store),
//!   exactly like the original.
//! - `mailbox_delete` — `FUN_080564b0` @ 0x080564b0 (60 bytes; 1 call
//!   site, `blne` @ 0x080a6bfc). Copies `block->id` to a stack slot, runs
//!   the task-lock/-unlock pair (thunks 0x08037e48 / 0x08037e50, ROM
//!   0x22003ea0 / 0x2200408c) with the id — the lock result is discarded —
//!   then the ROM delete dispatch (thunk 0x08037e40 -> ROM 0x22003dc8)
//!   with (opcode 2, &stack slot), zeroes `block->id` and frees the block
//!   via os_free. No NULL guard on `block`, faithful to the original.
//! - `waiter_create` — `FUN_08056788` @ 0x08056788 (32 bytes; 4 call
//!   sites, among them `condvar_wait` @ 0x0807f6ac). Zeroes a stack slot,
//!   ROM create dispatch (opcode 2, &slot), returns the id by value. The
//!   stock wrapper ignores whatever its caller left in r0.
//! - `waiter_delete` — `FUN_080564ec` @ 0x080564ec (36 bytes; 2 call
//!   sites). Same task-lock/-unlock pair on the id, then ROM delete
//!   dispatch (opcode 2, &stack copy of the id). Nothing is freed — the
//!   id was never heap-backed.
//! - `waiter_wait` — `FUN_0805695c` @ 0x0805695c (32 bytes). Sleeps on
//!   the object via thunk 0x08037ea0 -> ROM 0x220043c0 with (id,
//!   timeout), first clamping a zero timeout up to 1 tick; returns 1
//!   exactly when the ROM reported RTXC return code 5 (timeout), else 0.
//! - `waiter_wake` — `thunk_EXT_FUN_220041cc` @ 0x080567f8 (4 bytes:
//!   `b 0x08037e78`). Pure tail branch onto the thunk for ROM 0x220041cc —
//!   signal/wake the waiter object, r0 = id.
//!
//! On the task-lock pair: as documented in kernel/task_lock.rs, ROM
//! 0x22003ea0 is a table-indexed id -> object-pointer load and ROM
//! 0x2200408c dispatches kernel gateway service 3; the back-to-back use
//! around these delete paths is what the lock/unlock naming records.
//!
//! # Dispatch design (house pattern, deviation by necessity)
//!
//! The four ROM entry points live in the S5L8702 mask ROM, not in osos, so
//! they dispatch through the `KOBJ_HOOKS` fn-pointer table (defaults:
//! create spins — it cannot mint an object id; delete/lock/unlock are
//! harmless no-ops). The heap veneers `os_malloc`/`os_free` ARE ported
//! (kernel/os_heap.rs), so their slots default to the real functions —
//! on target no install is needed for them; host tests swap in mocks
//! because the real path would run the heap machinery (see os_heap.rs's
//! seam note). `read_volatile` on the table prevents LLVM from
//! constant-folding the default stubs (see sync_sem.rs).
//!
//! Wiring note for condvar.rs: `CONDVAR_HOOKS.waiter_create`/`waiter_delete`
//! type the waiter id as `*mut u32`; the id here is a plain `u32`. Both
//! are one register on the ARM target — cast at install time.

/// Dispatcher opcode for this object class (`mov r0, #0x2` at every
/// create/delete site here; opcode 1 = semaphores in sync_sem.rs).
const KOBJ2_OP: u32 = 2;

/// Heap-resident mailbox block (8 bytes, original layout).
#[repr(C)]
pub struct Mailbox {
    /// +0x00: zeroed by create, owned by the caller afterwards.
    pub state: u32,
    /// +0x04: kernel object id, written by the ROM create dispatcher and
    /// zeroed by delete.
    pub id: u32,
}

/// ROM/heap services this module depends on. Each member cites the osos
/// thunk it routes to.
#[derive(Clone, Copy)]
pub struct KobjHooks {
    /// ROM create dispatcher @ 0x22003d70 (thunk 0x08037e70): writes the
    /// new object id of class `op` into `*slot`.
    pub op_create: unsafe extern "C" fn(op: u32, slot: *mut u32),
    /// ROM delete dispatcher @ 0x22003dc8 (thunk 0x08037e40): deletes the
    /// class-`op` object whose id is in `*slot`.
    pub op_delete: unsafe extern "C" fn(op: u32, slot: *mut u32),
    /// ROM id lookup @ 0x22003ea0 (thunk 0x08037e48) — the "task lock"
    /// half of the pair; the original discards its result.
    pub task_lock: unsafe extern "C" fn(id: u32),
    /// ROM gateway service 3 @ 0x2200408c (thunk 0x08037e50) — the
    /// "task unlock" half.
    pub task_unlock: unsafe extern "C" fn(id: u32),
    /// Tag-0 heap alloc @ 0x080769b8 — ported, defaults to the real
    /// `os_malloc` (kernel/os_heap.rs).
    pub heap_alloc: unsafe extern "C" fn(size: usize) -> *mut u8,
    /// Tag-0 heap free @ 0x080f151c — ported, defaults to the real
    /// `os_free`.
    pub heap_free: unsafe extern "C" fn(ptr: *mut u8),
    /// ROM timed sleep @ 0x220043c0 (thunk 0x08037ea0): blocks on the
    /// object until signaled or `timeout` ticks pass; returns the RTXC
    /// return code (5 = timeout).
    pub rom_waiter_wait: unsafe extern "C" fn(id: u32, timeout: u32) -> u32,
    /// ROM signal @ 0x220041cc (thunk 0x08037e78): wakes the object's
    /// sleeper.
    pub rom_waiter_signal: unsafe extern "C" fn(id: u32),
}

/// RTXC return code 5: the timed sleep expired (`cmp r0, #0x5`).
pub const RTXC_RC_TIMEOUT: u32 = 5;

/// Default stub: no kernel, no object ids — spin rather than hand out an
/// uninitialized id (same contract as sync_sem's `missing_op_create`).
unsafe extern "C" fn missing_op_create(_op: u32, _slot: *mut u32) {
    loop {}
}

/// Default stub: deleting into a nonexistent kernel is a harmless no-op.
unsafe extern "C" fn missing_op_delete(_op: u32, _slot: *mut u32) {}

/// Default stub: the lock/unlock pair degrades to a no-op without the ROM.
unsafe extern "C" fn missing_task_lock(_id: u32) {}

/// Default stub: a sleep with nothing to wake it behaves like a timeout
/// (returning "signaled" would fake progress that never happened).
unsafe extern "C" fn missing_rom_waiter_wait(_id: u32, _timeout: u32) -> u32 {
    RTXC_RC_TIMEOUT
}

/// Default stub: waking into a nonexistent kernel is a harmless no-op.
unsafe extern "C" fn missing_rom_waiter_signal(_id: u32) {}

/// Shipped defaults: ROM slots are the documented stubs, heap slots are
/// the real ported veneers.
pub const DEFAULT_KOBJ_HOOKS: KobjHooks = KobjHooks {
    op_create: missing_op_create,
    op_delete: missing_op_delete,
    task_lock: missing_task_lock,
    task_unlock: missing_task_lock,
    heap_alloc: crate::kernel::os_heap::os_malloc,
    heap_free: crate::kernel::os_heap::os_free,
    rom_waiter_wait: missing_rom_waiter_wait,
    rom_waiter_signal: missing_rom_waiter_signal,
};

/// The active hook table. Written once at init on target; host tests
/// serialize access.
pub static mut KOBJ_HOOKS: KobjHooks = DEFAULT_KOBJ_HOOKS;

/// Reads the hook table (volatile — see the module header).
#[inline(always)]
fn hooks() -> KobjHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(KOBJ_HOOKS)) }
}

/// mailbox_create — original: `FUN_0805675c` @ 0x0805675c (44 bytes).
///
/// Allocates the 8-byte block, zeroes `state`, asks the ROM to create an
/// opcode-2 object into `id`, and returns the block. A failed allocation
/// is not checked (faithful): NULL faults on the `state` store.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mailbox_create() -> *mut Mailbox {
    let h = hooks();
    let block = (h.heap_alloc)(core::mem::size_of::<Mailbox>()) as *mut Mailbox;
    (*block).state = 0;
    (h.op_create)(KOBJ2_OP, core::ptr::addr_of_mut!((*block).id));
    block
}

/// mailbox_delete — original: `FUN_080564b0` @ 0x080564b0 (60 bytes).
///
/// Task-lock/-unlock on the id, ROM delete of the opcode-2 object (via a
/// stack copy of the id, exactly like the original), zero the id, free
/// the block. No NULL guard on `block` (faithful).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mailbox_delete(block: *mut Mailbox) {
    let h = hooks();
    let mut id = (*block).id;
    (h.task_lock)(id);
    (h.task_unlock)(id);
    (h.op_delete)(KOBJ2_OP, &mut id);
    (*block).id = 0;
    (h.heap_free)(block as *mut u8);
}

/// waiter_create — original: `FUN_08056788` @ 0x08056788 (32 bytes).
///
/// Creates an opcode-2 object into a zeroed stack slot and returns the
/// kernel object id by value.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn waiter_create() -> u32 {
    let mut slot: u32 = 0;
    (hooks().op_create)(KOBJ2_OP, &mut slot);
    slot
}

/// waiter_delete — original: `FUN_080564ec` @ 0x080564ec (36 bytes).
///
/// Task-lock/-unlock on the id, then ROM delete via a stack copy of the
/// id. Nothing is freed.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn waiter_delete(id: u32) {
    let h = hooks();
    let mut slot = id;
    (h.task_lock)(id);
    (h.task_unlock)(id);
    (h.op_delete)(KOBJ2_OP, &mut slot);
}

/// waiter_wait — original: `FUN_0805695c` @ 0x0805695c (32 bytes).
///
/// Timed sleep on the waiter object (zero timeout clamped to 1 tick);
/// returns 1 on RTXC timeout (code 5), 0 when signaled.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn waiter_wait(id: u32, timeout: u32) -> u32 {
    let ticks = if timeout == 0 { 1 } else { timeout };
    ((hooks().rom_waiter_wait)(id, ticks) == RTXC_RC_TIMEOUT) as u32
}

/// waiter_wake — original: `thunk_EXT_FUN_220041cc` @ 0x080567f8
/// (4 bytes).
///
/// Tail branch onto the ROM signal — wakes the object's sleeper.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn waiter_wake(id: u32) {
    (hooks().rom_waiter_signal)(id);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    /// Serializes tests that swap the global hook table.
    static HOOKS_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Create { op: u32, slot: usize },
        Delete { op: u32, slot: usize, slot_value: u32 },
        Lock(u32),
        Unlock(u32),
        Alloc(usize),
        Free(usize),
        Wait { id: u32, timeout: u32 },
        Wake(u32),
    }

    static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());

    /// Object id the mock ROM create writes into the slot.
    const MOCK_ID: u32 = 0x0b0e_0002;

    /// Backing store the mock allocator hands out.
    static mut ALLOC_CELL: Mailbox = Mailbox {
        state: 0xdead_beef,
        id: 0xdead_beef,
    };

    unsafe extern "C" fn mock_op_create(op: u32, slot: *mut u32) {
        CALLS.lock().unwrap().push(Call::Create {
            op,
            slot: slot as usize,
        });
        *slot = MOCK_ID;
    }

    unsafe extern "C" fn mock_op_delete(op: u32, slot: *mut u32) {
        CALLS.lock().unwrap().push(Call::Delete {
            op,
            slot: slot as usize,
            slot_value: *slot,
        });
    }

    unsafe extern "C" fn mock_lock(id: u32) {
        CALLS.lock().unwrap().push(Call::Lock(id));
    }

    unsafe extern "C" fn mock_unlock(id: u32) {
        CALLS.lock().unwrap().push(Call::Unlock(id));
    }

    unsafe extern "C" fn mock_alloc(size: usize) -> *mut u8 {
        CALLS.lock().unwrap().push(Call::Alloc(size));
        core::ptr::addr_of_mut!(ALLOC_CELL) as *mut u8
    }

    unsafe extern "C" fn mock_free(ptr: *mut u8) {
        CALLS.lock().unwrap().push(Call::Free(ptr as usize));
    }

    /// RTXC return code the mock sleep reports.
    static mut WAIT_RC: u32 = 0;

    unsafe extern "C" fn mock_wait(id: u32, timeout: u32) -> u32 {
        CALLS.lock().unwrap().push(Call::Wait { id, timeout });
        WAIT_RC
    }

    unsafe extern "C" fn mock_wake(id: u32) {
        CALLS.lock().unwrap().push(Call::Wake(id));
    }

    /// Installs the mock table, clears the log, returns the guard.
    fn mock_hooks() -> MutexGuard<'static, ()> {
        let guard = HOOKS_LOCK.lock().unwrap();
        unsafe {
            core::ptr::addr_of_mut!(ALLOC_CELL).write(Mailbox {
                state: 0xdead_beef,
                id: 0xdead_beef,
            });
            WAIT_RC = 0;
            core::ptr::addr_of_mut!(KOBJ_HOOKS).write(KobjHooks {
                op_create: mock_op_create,
                op_delete: mock_op_delete,
                task_lock: mock_lock,
                task_unlock: mock_unlock,
                heap_alloc: mock_alloc,
                heap_free: mock_free,
                rom_waiter_wait: mock_wait,
                rom_waiter_signal: mock_wake,
            });
        }
        CALLS.lock().unwrap().clear();
        guard
    }

    fn drain() -> Vec<Call> {
        core::mem::take(&mut *CALLS.lock().unwrap())
    }

    #[test]
    fn mailbox_create_allocates_zeroes_and_dispatches() {
        let _guard = mock_hooks();
        unsafe {
            let block = mailbox_create();
            assert_eq!(block, core::ptr::addr_of_mut!(ALLOC_CELL));
            assert_eq!((*block).state, 0, "state word zeroed");
            assert_eq!((*block).id, MOCK_ID, "ROM wrote the id into +4");
            let id_slot = core::ptr::addr_of_mut!((*block).id) as usize;
            assert_eq!(
                drain(),
                vec![
                    Call::Alloc(8),
                    Call::Create {
                        op: 2,
                        slot: id_slot
                    }
                ]
            );
        }
    }

    #[test]
    fn mailbox_delete_locks_dispatches_on_copy_and_frees() {
        let _guard = mock_hooks();
        unsafe {
            let block = core::ptr::addr_of_mut!(ALLOC_CELL);
            (*block).id = 0x77;
            mailbox_delete(block);
            assert_eq!((*block).id, 0, "id zeroed before the free");
            let calls = drain();
            assert_eq!(calls.len(), 4);
            assert_eq!(calls[0], Call::Lock(0x77));
            assert_eq!(calls[1], Call::Unlock(0x77));
            // The delete dispatch gets a STACK copy of the id, not the
            // block's own slot (faithful to the original).
            match calls[2] {
                Call::Delete {
                    op,
                    slot,
                    slot_value,
                } => {
                    assert_eq!(op, 2);
                    assert_eq!(slot_value, 0x77);
                    assert_ne!(
                        slot,
                        core::ptr::addr_of_mut!((*block).id) as usize,
                        "dispatch must not target the block's id word"
                    );
                }
                ref other => panic!("expected Delete, got {other:?}"),
            }
            assert_eq!(calls[3], Call::Free(block as usize));
        }
    }

    #[test]
    fn waiter_create_returns_the_id_from_a_zeroed_slot() {
        let _guard = mock_hooks();
        unsafe {
            assert_eq!(waiter_create(), MOCK_ID);
            let calls = drain();
            assert_eq!(calls.len(), 1);
            match calls[0] {
                Call::Create { op, .. } => assert_eq!(op, 2),
                ref other => panic!("expected Create, got {other:?}"),
            }
        }
    }

    #[test]
    fn waiter_create_returns_zero_when_rom_writes_nothing() {
        let _guard = mock_hooks();
        unsafe extern "C" fn create_noop(_op: u32, _slot: *mut u32) {}
        unsafe {
            (*core::ptr::addr_of_mut!(KOBJ_HOOKS)).op_create = create_noop;
            // The slot is zero-initialized, so a silent dispatcher yields 0.
            assert_eq!(waiter_create(), 0);
        }
    }

    #[test]
    fn waiter_delete_locks_and_dispatches_a_copy() {
        let _guard = mock_hooks();
        unsafe {
            waiter_delete(0x1234);
            let calls = drain();
            assert_eq!(calls.len(), 3);
            assert_eq!(calls[0], Call::Lock(0x1234));
            assert_eq!(calls[1], Call::Unlock(0x1234));
            match calls[2] {
                Call::Delete { op, slot_value, .. } => {
                    assert_eq!(op, 2);
                    assert_eq!(slot_value, 0x1234);
                }
                ref other => panic!("expected Delete, got {other:?}"),
            }
        }
    }

    #[test]
    fn waiter_wait_clamps_zero_timeout_and_maps_rc5() {
        let _guard = mock_hooks();
        unsafe {
            // Timeout expired -> 1; zero timeout is clamped to 1 tick.
            WAIT_RC = RTXC_RC_TIMEOUT;
            assert_eq!(waiter_wait(0x42, 0), 1);
            assert_eq!(drain(), vec![Call::Wait { id: 0x42, timeout: 1 }]);
            // Signaled (any code but 5) -> 0; nonzero timeout unchanged.
            WAIT_RC = 0;
            assert_eq!(waiter_wait(0x42, 250), 0);
            assert_eq!(
                drain(),
                vec![Call::Wait {
                    id: 0x42,
                    timeout: 250
                }]
            );
        }
    }

    #[test]
    fn waiter_wake_forwards_the_id() {
        let _guard = mock_hooks();
        unsafe {
            waiter_wake(0x99);
            assert_eq!(drain(), vec![Call::Wake(0x99)]);
        }
    }

    #[test]
    fn default_heap_slots_are_the_real_veneers() {
        // The shipped defaults must wire the ported os_malloc/os_free, so
        // on target no install is needed for the heap half of the table.
        assert_eq!(
            DEFAULT_KOBJ_HOOKS.heap_alloc as usize,
            crate::kernel::os_heap::os_malloc as usize
        );
        assert_eq!(
            DEFAULT_KOBJ_HOOKS.heap_free as usize,
            crate::kernel::os_heap::os_free as usize
        );
    }
}

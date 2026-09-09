//! `event_code_queue_post` — original: `FUN_081de270` @ **0x081de270**
//! (**40 bytes** exactly, 0x081de270..0x081de298; the next function — the
//! base-class ctor — opens `push {r4, r5, r6, r7, r8, lr}` @ 0x081de298,
//! and there is no literal pool, so Ghidra's 40 is right). **16 `bl`-form
//! call sites, verified by decoding every B/BL word in osos.dec**: 11
//! plain `bl`, 1 `blne` and 4 `bleq`. The predicated sites gate on the
//! *caller's* own incoming-event checks (e.g. @ 0x081a565c/0x081a5680 the
//! caller compares the event kind word against 6/0xd and the payload code
//! against 0x1c/0x3b), never on queue state — the callee itself has no
//! guards. No tail `b` sites, and a full data-word scan finds no
//! reference to 0x081de270: the method is never dispatched virtually.
//!
//! # What it is
//!
//! A method of the deferred event-code queue base class (base ctor @
//! 0x081de298, vtable 0x0898e9b0; derived into registry class 0x8c00 —
//! `singleton_class_8c00` @ 0x081a5500, ported in `app/singletons` —
//! through the intermediate ctor @ 0x08143efc). Event handlers translate
//! an incoming event into a small integer code and post it here for the
//! object's own context to drain later: observed codes are 0, 6, 7, 8,
//! 0xb, 0xd, 0x14, 0x15, 0x16, 0x17, 0x1a and 0x1b. The queue push @
//! 0x083dfeb8 has exactly two callers in the whole image — this function
//! and the bulk-seed helper 0x083ea558 used by the base ctor — so this
//! method is the class's sole runtime enqueue point.
//!
//! # Algorithm
//!
//! ```text
//! push {r0, r1, r4, lr}             ; sp+4 = stack copy of `code`
//! mutex_lock(&this->mutex_34);      ; 0x0807f5c4 (ported, kernel/sync_mutex)
//! queue_push_u32(&this->queue_08, &code);  ; 0x083dfeb8 (unported)
//! mutex_unlock(&this->mutex_34);    ; 0x0807f6a0 (ported, kernel/sync_mutex)
//! pop  {r2, r3, r4, pc}             ; scratch slots discarded
//! ```
//!
//! Void: the original leaves r0 holding whatever `mutex_unlock` returned
//! and no caller reads it.
//!
//! # Layout (target)
//!
//! ```text
//! +0x00  vtable (0x0898e9b0 in the base ctor) — never read here
//! +0x04  untouched by the base ctor (alignment pad)
//! +0x08  queue container, 0x28 bytes (count word at container+0x20 per
//!        the ported container_is_empty family @ 0x083d75e0)
//! +0x30  word the base ctor zeroes
//! +0x34  Mutex (8 bytes) — base size is 0x3c: the derived ctor @
//!        0x08143efc starts its own fields at +0x3c (binary-verified)
//! ```
//!
//! # Deviations
//!
//! The queue push @ 0x083dfeb8 is unported — it is an ADS STL
//! vector/deque `push_back` with a grow path through 0x083df988 /
//! `operator_new` — so it rides [`EVENT_CODE_QUEUE_HOOKS`]. The default
//! stub drops the code: inert, and it never invents behavior — with the
//! default table the port is NOT hook-ready (the queue never fills)
//! until the container family is ported. `mutex_lock`/`mutex_unlock`
//! are already ported and are called directly (the
//! `kernel/mutex_handoff` precedent), so target code may inline their
//! ROM-dispatch guards rather than retain the two retail call
//! boundaries.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// The event-code queue object the original method runs on. Named
/// `repr(C)` fields keep the port off literal byte offsets; on the
/// 32-bit target every field is 4-aligned and the mutex lands at +0x34,
/// exactly the stock layout.
#[repr(C)]
pub struct EventCodeQueue {
    /// +0x00: class vtable (0x0898e9b0 from the base ctor). Never read
    /// by this port.
    pub vtable: *const u32,
    /// +0x04: word no method of the base class touches.
    pub pad_04: u32,
    /// +0x08: the u32 queue container (0x28 bytes), opaque here — only
    /// the unported push @ 0x083dfeb8 interprets it.
    pub queue: [u32; 10],
    /// +0x30: word the base ctor zeroes.
    pub word_30: u32,
    /// +0x34: the mutex guarding every enqueue.
    pub mutex: Mutex,
}

/// The one unported callee, behind the crate's dispatch-table pattern
/// (the `kernel/resource_op` precedent).
#[derive(Copy, Clone)]
pub struct EventCodeQueueHooks {
    /// Queue push @ 0x083dfeb8: appends `*code` to the container,
    /// growing it first when it is empty or full. Called with the
    /// mutex held, exactly as the original does.
    pub enqueue: unsafe extern "C" fn(queue: *mut u8, code: *const u32),
}

/// Default enqueue stub: the container push is unported, so the code is
/// dropped. Inert — with this default the queue never fills and the port
/// is NOT hook-ready (see the module header).
pub unsafe extern "C" fn dropped_enqueue(_queue: *mut u8, _code: *const u32) {}

/// The active enqueue callee. Replace before first use on target; host
/// tests install a recorder via `core::ptr::addr_of_mut!`.
pub static mut EVENT_CODE_QUEUE_HOOKS: EventCodeQueueHooks = EventCodeQueueHooks {
    enqueue: dropped_enqueue,
};

/// Reads the hook table. Volatile so LLVM cannot constant-fold the load
/// to the default stub (the table is meant to be swapped at runtime).
#[inline(always)]
fn hooks() -> EventCodeQueueHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_CODE_QUEUE_HOOKS)) }
}

/// Posts `code` to the object's queue under its mutex.
///
/// Original: `FUN_081de270` @ 0x081de270 (40 bytes; 16 `bl`-form call
/// sites, binary-verified — see the module header).
///
/// # Safety
///
/// `this` must point at a live queue object (at least 0x3c bytes,
/// word-aligned) whose mutex at +0x34 was created by the base ctor, and
/// the installed `enqueue` hook must be callable with the queue base and
/// a `u32` pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn event_code_queue_post(this: *mut EventCodeQueue, code: u32) {
    let mutex = core::ptr::addr_of_mut!((*this).mutex);
    mutex_lock(mutex);
    (hooks().enqueue)(core::ptr::addr_of_mut!((*this).queue) as *mut u8, &code);
    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::Mutex as HostMutex;

    /// Serializes this module's swaps of the global ROM table and the
    /// module's own hook table (cargo test runs tests on parallel
    /// threads).
    static ROM_LOCK: HostMutex<()> = HostMutex::new(());

    /// Takes both serializing locks in a fixed order (shared table lock
    /// first, then this module's ROM_LOCK) so the
    /// `app::class_8c00` timer-rearm tests — which swap
    /// EVENT_CODE_QUEUE_HOOKS under the shared lock — cannot race these
    /// tests' table swaps.
    fn lock_tables() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let shared = crate::testing::EVENT_CODE_QUEUE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let rom = ROM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        (shared, rom)
    }

    const MAX_EVENTS: usize = 8;
    static EVENT_COUNT: AtomicUsize = AtomicUsize::new(0);
    /// Tag in the top byte: 0x01 = sema_wait, 0x02 = sema_signal,
    /// 0x03 = enqueue; the low bytes carry the handle or posted code.
    static EVENTS: [AtomicU32; MAX_EVENTS] = [
        AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
        AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    ];
    static QUEUE_ARG: AtomicUsize = AtomicUsize::new(0);

    fn record(tag: u32, arg: u32) {
        let slot = EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
        if slot < MAX_EVENTS {
            EVENTS[slot].store(tag << 24 | arg, Ordering::SeqCst);
        }
    }

    unsafe extern "C" fn record_wait(handle: u32) {
        record(1, handle);
    }

    unsafe extern "C" fn record_signal(handle: u32) {
        record(2, handle);
    }

    unsafe extern "C" fn record_enqueue(queue: *mut u8, code: *const u32) {
        QUEUE_ARG.store(queue as usize, Ordering::SeqCst);
        record(3, *code);
    }

    fn events() -> std::vec::Vec<u32> {
        let n = EVENT_COUNT.load(Ordering::SeqCst).min(MAX_EVENTS);
        (0..n).map(|i| EVENTS[i].load(Ordering::SeqCst)).collect()
    }

    struct TableGuard(RomKernelOps, EventCodeQueueHooks);

    /// Installs the recording mocks; restores both tables on drop.
    fn install_mocks() -> TableGuard {
        let saved_rom = unsafe { core::ptr::addr_of!(ROM_KERNEL).read_volatile() };
        let saved_hooks = unsafe { core::ptr::addr_of!(EVENT_CODE_QUEUE_HOOKS).read_volatile() };
        let patched = RomKernelOps {
            sema_wait: record_wait,
            sema_signal: record_signal,
            ..saved_rom
        };
        unsafe {
            core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(patched);
            core::ptr::addr_of_mut!(EVENT_CODE_QUEUE_HOOKS).write_volatile(EventCodeQueueHooks {
                enqueue: record_enqueue,
            });
        }
        EVENT_COUNT.store(0, Ordering::SeqCst);
        QUEUE_ARG.store(0, Ordering::SeqCst);
        TableGuard(saved_rom, saved_hooks)
    }

    impl Drop for TableGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(self.0);
                core::ptr::addr_of_mut!(EVENT_CODE_QUEUE_HOOKS).write_volatile(self.1);
            }
        }
    }

    fn fixture(cell: *mut u32) -> EventCodeQueue {
        EventCodeQueue {
            vtable: core::ptr::null(),
            pad_04: 0,
            queue: [0xdead_beef; 10],
            word_30: 0,
            mutex: Mutex { sem_cell: cell, unused: 0 },
        }
    }

    #[test]
    fn posts_code_with_mutex_held() {
        let _guards = lock_tables();
        let _tables = install_mocks();
        let mut handle = 0x42u32;
        let mut object = fixture(&mut handle);

        unsafe { event_code_queue_post(&mut object, 0x16) };

        assert_eq!(
            events(),
            [0x0100_0042, 0x0300_0016, 0x0200_0042],
            "enqueue must be bracketed by wait/signal on the mutex handle",
        );
        assert_eq!(
            QUEUE_ARG.load(Ordering::SeqCst),
            core::ptr::addr_of_mut!(object.queue) as usize,
            "the push must receive the container at this+0x08",
        );
    }

    #[test]
    fn null_mutex_cell_still_enqueues() {
        let _guards = lock_tables();
        let _tables = install_mocks();
        let mut object = fixture(core::ptr::null_mut());

        unsafe { event_code_queue_post(&mut object, 0x1b) };

        assert_eq!(
            events(),
            [0x0300_001b],
            "a NULL cell makes lock/unlock no-ops but the code still posts",
        );
    }

    #[test]
    fn zero_handle_cell_skips_rom_but_enqueues() {
        let _guards = lock_tables();
        let _tables = install_mocks();
        let mut handle = 0u32;
        let mut object = fixture(&mut handle);

        unsafe { event_code_queue_post(&mut object, 7) };

        assert_eq!(
            events(),
            [0x0300_0007],
            "a zero semaphore handle reaches no ROM wait/signal",
        );
    }

    #[test]
    fn default_enqueue_drops_without_touching_queue() {
        let _guards = lock_tables();
        let saved_rom = unsafe { core::ptr::addr_of!(ROM_KERNEL).read_volatile() };
        let patched = RomKernelOps {
            sema_wait: record_wait,
            sema_signal: record_signal,
            ..saved_rom
        };
        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(patched) };
        EVENT_COUNT.store(0, Ordering::SeqCst);
        let mut object = fixture(core::ptr::null_mut());

        // EVENT_CODE_QUEUE_HOOKS is at its default here: the code is
        // dropped and the container stays untouched.
        unsafe { event_code_queue_post(&mut object, 0x15) };

        assert_eq!(events(), std::vec::Vec::<u32>::new());
        assert_eq!(object.queue, [0xdead_beef; 10]);
        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(saved_rom) };
    }
}

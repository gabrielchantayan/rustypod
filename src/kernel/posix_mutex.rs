//! The C++ layer's owner-tracked mutex — the lock/unlock pair every
//! block-manager client, pool base and heap region brackets its critical
//! sections with. This is NOT the RTXC mutex of kernel/sync_mutex.rs
//! (0x080744a4 & co., a bare counting semaphore with no owner state);
//! this one carries an owner thread, a recursion count and a kind, and
//! sits *on top of* a counting semaphore held inline at +0x14.
//!
//! - `posix_mutex_lock` — original: `FUN_082e8390` @ 0x082e8390
//!   (**72 bytes**, 0x082e8390..0x082e83d8: 68 bytes of code plus the
//!   4-byte literal `STATIC_INIT_MAGIC` @ 0x082e83d4. Ghidra claims 320
//!   bytes — wrong; its extent swallows the unlock and two of its
//!   siblings. Byte-decoded from osos.dec).
//!   **240 call sites**, binary-verified by decoding every B/BL word in
//!   osos.dec: 2 direct `bl` (0x080c9848, 0x080c9884) plus the two
//!   4-byte alias veneers below.
//! - `posix_mutex_unlock` — original: `FUN_082e83d8` @ 0x082e83d8
//!   (**156 bytes**, 0x082e83d8..0x082e8474: 152 bytes of code plus the
//!   4-byte literal @ 0x082e8470 — Ghidra's 152 drops that literal).
//!   **266 call sites**: 1 direct `bl` (0x080c97ac) plus the veneers.
//! - `posix_mutex_lock_deadline` — original: `FUN_080cdd6c` @ 0x080cdd6c
//!   (**256 bytes**, 0x080cdd6c..0x080cde6c, including the trailing
//!   `NANOS_PER_SEC` literal @ 0x080cde68). Exactly **1** reference in
//!   the whole image — the lock's tail `b` @ 0x082e83d0 — so the
//!   deadline half of the interface is reachable only through the
//!   blocking wrapper in this ROM. Ghidra inlined it into `FUN_082e8390`
//!   and then mis-sized the result; it is a real, separately linked
//!   function and is ported as one.
//!
//! ## The four alias veneers
//!
//! Two identical veneer blocks (one per calling region — the linker
//! emitted a duplicate pair so that far callers stay in `bl` range)
//! forward to the pair. Each is a single 4-byte `b`, i.e. nothing to
//! port: the veneer address *is* the function for every caller that
//! reaches it. Verified call counts (every B/BL word decoded):
//!
//! | veneer     | `b` target       | `bl` sites | tail `b` sites |
//! |------------|------------------|-----------:|---------------:|
//! | 0x08261e20 | lock @0x082e8390 |        156 |              1 |
//! | 0x08261e24 | unlock@0x082e83d8|        153 |             12 |
//! | 0x082621a8 | lock @0x082e8390 |         78 |              3 |
//! | 0x082621ac | unlock@0x082e83d8|         76 |             24 |
//!
//! ## The object
//!
//! [`PosixMutex`] is 24 bytes and, unusually for this crate, has **no
//! pointer fields** — every member is a `u32`/`u16`, so the `repr(C)`
//! layout is byte-identical on the 32-bit target and on a 64-bit test
//! host (asserted below). The semaphore is not a pointer either: the
//! ROM handle lives inline at +0x14 and the semaphore helpers take that
//! slot's address.
//!
//! ## Algorithm
//!
//! Both entry points start the same way: a NULL object returns
//! [`ERR_INVALID_OBJECT`], and an object still carrying
//! [`STATIC_INIT_MAGIC`] (the value a statically-initialized mutex is
//! born with) is run through the lazy initializer @ 0x082e82f8 first,
//! whose error, if any, is returned verbatim.
//!
//! `posix_mutex_lock` then tail-branches into the deadline core with a
//! NULL deadline. The core:
//!
//! 1. reads the kind — bits 4..5 of the halfword at +0xe, i.e. of the
//!    high half of the attr word the initializer copied to +0xc
//!    (`ldrh` + `lsl #26` + `lsr #30`): 0 normal, 1 error-checking,
//!    2 recursive;
//! 2. asks who is running (0x080a3e68) and compares against the owner
//!    at +0x4. **If we already hold it**: a recursive mutex bumps the
//!    16-bit count at +0x12 and returns, unless the count has reached
//!    `0xffff`, which is [`ERR_RECURSION_OVERFLOW`] (the original's
//!    `subs`/`subscs` carry chain against 0xff00 then 0xff); an
//!    error-checking mutex returns [`ERR_WOULD_DEADLOCK`]; a normal
//!    mutex falls through and blocks on itself, which is what a normal
//!    mutex is specified to do;
//! 3. otherwise waits on the inline semaphore — 0x080a3c7c with no
//!    deadline, or, with one, 0x080a3ca4 after converting the absolute
//!    deadline into a relative wait: read now (0x082c372c, clock 0 —
//!    its error is returned as-is, *not* laundered through the result
//!    register), subtract field-wise, then normalize a negative
//!    nanosecond field by borrowing whole seconds;
//! 4. on a successful wait, claims the mutex: owner := us, count := 1.
//!
//! `posix_mutex_unlock` is self-contained: a non-owner gets
//! [`ERR_NOT_OWNER`]; a recursive mutex decrements the count and stops
//! there while it stays nonzero; otherwise the count and owner are
//! cleared and the semaphore is signalled (0x080a3d30), whose status is
//! the return value.
//!
//! # Deviations
//!
//! - **Unported callees dispatch through [`POSIX_MUTEX_OPS`]** (house
//!   ops-slot pattern, indirect `blx` in place of `bl`): the lazy
//!   initializer @ 0x082e82f8, the running-thread query @ 0x080a3e68,
//!   the three semaphore helpers @ 0x080a3c7c / 0x080a3ca4 /
//!   0x080a3d30 and the clock read @ 0x082c372c all bottom out in the
//!   mask-ROM kernel, which is not part of osos. The defaults model the
//!   pre-kernel machine and are documented on each stub; together they
//!   give a mutex that tracks ownership and recursion faithfully but
//!   provides **no mutual exclusion** — exactly the contract the
//!   `REGION_MUTEX_OPS` no-op stubs this port replaces used to state.
//! - **The initializer default does nothing and reports success.**
//!   Without the ROM there is no semaphore to create; the object is
//!   then used as it stands. In practice the slot never fires on host:
//!   every fixture in this crate is zeroed or garbage-filled memory,
//!   never [`STATIC_INIT_MAGIC`].
//! - The two magic literals (0x082e83d4 for the lock, 0x082e8470 for
//!   the unlock) hold the same word and are modeled as one constant.
//! - Arithmetic that can wrap in the original's bare `add`/`sub`
//!   (deadline subtraction, the recursion decrement) uses the explicit
//!   `wrapping_*` forms so a debug host build cannot panic where the
//!   ARM code silently wraps.

/// Width of the mutex's recursion counter, and the value at which one
/// more acquire is refused (original: the `subs r12, r0, #0xff00` /
/// `subscs r12, r12, #0xff` carry chain, which clears carry exactly for
/// counts below 0xffff).
const RECURSION_LIMIT: u16 = u16::MAX;

/// Nanoseconds per second — the original's literal @ 0x080cde68,
/// added back into a borrowed nanosecond field.
const NANOS_PER_SEC: i32 = 1_000_000_000;

/// Clock selector the deadline path reads "now" from (original:
/// `mov r0, #0` ahead of `bl 0x082c372c`).
const CLOCK_WALL: u32 = 0;

/// The word a statically-initialized mutex is born with (literals
/// @ 0x082e83d4 and 0x082e8470; bytes `S X T M`). Seeing it means the
/// object has never been through the initializer.
pub const STATIC_INIT_MAGIC: u32 = 0x4d54_5853;

/// Returned for a NULL mutex — and by the initializer for an object it
/// cannot recognize (original: `mov r0, #0x1a`).
pub const ERR_INVALID_OBJECT: u32 = 0x1a;

/// An error-checking mutex re-locked by the thread that already holds
/// it (original: `moveq r5, #0xf`).
pub const ERR_WOULD_DEADLOCK: u32 = 0x0f;

/// A recursive mutex acquired past [`RECURSION_LIMIT`] holds
/// (original: `mov r5, #0x27`).
pub const ERR_RECURSION_OVERFLOW: u32 = 0x27;

/// Unlock attempted by a thread that does not own the mutex
/// (original: `movne r5, #0x5`).
pub const ERR_NOT_OWNER: u32 = 0x05;

/// Absolute or relative time, two 32-bit fields — the shape the clock
/// read fills and the timed semaphore wait consumes (the original
/// builds both on the stack as two words).
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct TimeSpec {
    pub sec: i32,
    pub nsec: i32,
}

/// What a mutex does when its owner locks it again — bits 4..5 of the
/// halfword at +0xe. Two bits, four values, so the mapping is total:
/// there is no "invalid kind" state to check for later.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MutexKind {
    /// 0 — no owner check on the fast path; re-locking blocks forever.
    Normal,
    /// 1 — re-locking by the owner is refused with
    /// [`ERR_WOULD_DEADLOCK`].
    ErrorCheck,
    /// 2 — re-locking by the owner bumps the recursion count.
    Recursive,
    /// 3 — unused by this ROM; the original tests only for 2 then 1, so
    /// it behaves like [`MutexKind::Normal`].
    Reserved,
}

impl MutexKind {
    /// Parses the two kind bits. Total by construction.
    const fn from_bits(bits: u16) -> Self {
        match bits & 3 {
            0 => MutexKind::Normal,
            1 => MutexKind::ErrorCheck,
            2 => MutexKind::Recursive,
            _ => MutexKind::Reserved,
        }
    }
}

/// The mutex object: 24 bytes, all-scalar, identical on target and host.
#[repr(C)]
pub struct PosixMutex {
    /// +0x00 — [`STATIC_INIT_MAGIC`] until the initializer runs, then
    /// the "live object" word the initializer writes.
    pub magic: u32,
    /// +0x04 — owning thread, 0 when unheld. Compared against the
    /// running-thread query; the ROM never hands out thread 0.
    pub owner: u32,
    /// +0x08 — zeroed by the initializer, never read by the pair.
    pub reserved_08: u32,
    /// +0x0c — the attribute word copied from the attr object. Only its
    /// high halfword (+0x0e) is read, and only bits 4..5 of that: the
    /// [`MutexKind`].
    pub attr_flags: u32,
    /// +0x10 — halfword the pair never touches.
    pub reserved_10: u16,
    /// +0x12 — recursion count: 1 for a plain hold, more for a
    /// recursive mutex re-locked by its owner.
    pub recursion: u16,
    /// +0x14 — the inline counting semaphore: a ROM handle cell, whose
    /// *address* is what the semaphore helpers take.
    pub sem_handle: u32,
}

// Target-exact layout (and, because nothing here is a pointer, the
// host layout too).
const _: () = assert!(core::mem::size_of::<PosixMutex>() == 0x18);
const _: () = assert!(core::mem::offset_of!(PosixMutex, owner) == 0x04);
const _: () = assert!(core::mem::offset_of!(PosixMutex, attr_flags) == 0x0c);
const _: () = assert!(core::mem::offset_of!(PosixMutex, recursion) == 0x12);
const _: () = assert!(core::mem::offset_of!(PosixMutex, sem_handle) == 0x14);

/// Indirect dispatch table for the mask-ROM-backed callees (see the
/// module header for the design and each default's contract).
#[derive(Clone, Copy)]
pub struct PosixMutexOps {
    /// Lazy initializer @ 0x082e82f8 `(mutex, attr)`; the pair always
    /// passes a NULL attr, which selects the process-wide default attr
    /// object @ 0x089cfcbc. Returns 0 or an error to propagate.
    pub init_static: unsafe extern "C" fn(mutex: *mut PosixMutex, attr: *mut u8) -> u32,
    /// Running-thread query @ 0x080a3e68. Never 0 on device.
    pub current_thread: unsafe extern "C" fn() -> u32,
    /// Blocking semaphore wait @ 0x080a3c7c `(&mutex.sem_handle)`.
    pub sem_acquire: unsafe extern "C" fn(cell: *mut u32) -> u32,
    /// Bounded semaphore wait @ 0x080a3ca4 `(&mutex.sem_handle,
    /// &relative_timeout)`.
    pub sem_acquire_timed:
        unsafe extern "C" fn(cell: *mut u32, timeout: *const TimeSpec) -> u32,
    /// Semaphore signal @ 0x080a3d30 `(&mutex.sem_handle)`.
    pub sem_release: unsafe extern "C" fn(cell: *mut u32) -> u32,
    /// Clock read @ 0x082c372c `(clock_id, out)`, called with clock 0.
    pub clock_now: unsafe extern "C" fn(clock_id: u32, out: *mut TimeSpec) -> u32,
}

/// The thread the default [`PosixMutexOps::current_thread`] reports.
/// Any nonzero value works — it only has to differ from the 0 an
/// unheld mutex carries in its owner field, so that a fresh object is
/// correctly seen as *unheld* rather than as "held by us".
pub const PRE_KERNEL_THREAD: u32 = 1;

/// Default: no semaphore layer, so there is nothing to initialize —
/// report success and let the object be used as it stands.
unsafe extern "C" fn missing_init_static(_mutex: *mut PosixMutex, _attr: *mut u8) -> u32 {
    0
}

/// Default: before the kernel runs there is exactly one thread.
unsafe extern "C" fn missing_current_thread() -> u32 {
    PRE_KERNEL_THREAD
}

/// Default: without the ROM semaphore every wait succeeds immediately —
/// ownership and recursion are still tracked, but there is no mutual
/// exclusion (the module header's contract).
unsafe extern "C" fn missing_sem_acquire(_cell: *mut u32) -> u32 {
    0
}

/// Default: see [`missing_sem_acquire`]; a wait that never blocks never
/// times out either.
unsafe extern "C" fn missing_sem_acquire_timed(
    _cell: *mut u32,
    _timeout: *const TimeSpec,
) -> u32 {
    0
}

/// Default: see [`missing_sem_acquire`].
unsafe extern "C" fn missing_sem_release(_cell: *mut u32) -> u32 {
    0
}

/// Default: no clock — report the epoch, successfully. Every deadline
/// then measures from 0, which only affects the (device-unreachable,
/// see the module header) deadline path.
unsafe extern "C" fn missing_clock_now(_clock_id: u32, out: *mut TimeSpec) -> u32 {
    *out = TimeSpec::default();
    0
}

/// Wired defaults (documented stubs — the ROM is not part of osos).
pub const DEFAULT_POSIX_MUTEX_OPS: PosixMutexOps = PosixMutexOps {
    init_static: missing_init_static,
    current_thread: missing_current_thread,
    sem_acquire: missing_sem_acquire,
    sem_acquire_timed: missing_sem_acquire_timed,
    sem_release: missing_sem_release,
    clock_now: missing_clock_now,
};

/// The active implementation. Host tests install mocks; on target the
/// kernel layer installs the real ROM helpers.
pub static mut POSIX_MUTEX_OPS: PosixMutexOps = DEFAULT_POSIX_MUTEX_OPS;

/// Reads the ops table (volatile — the slot is meant to be swapped at
/// runtime, and LLVM would otherwise fold the indirect calls to the
/// defaults).
#[inline(always)]
fn ops() -> PosixMutexOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(POSIX_MUTEX_OPS)) }
}

/// The kind bits: `ldrh r0, [mutex, #0xe]` then `lsl #26` / `lsr #30`.
#[inline(always)]
unsafe fn mutex_kind(mutex: *const PosixMutex) -> MutexKind {
    let attr_high = ((*mutex).attr_flags >> 16) as u16;
    MutexKind::from_bits(attr_high >> 4)
}

/// Runs the lazy initializer when the object still carries
/// [`STATIC_INIT_MAGIC`]; `Err` is the status the caller must return.
///
/// Shared prologue of both entry points (`ldr`/`cmp` against the magic
/// literal, then `bl 0x082e82f8` with a NULL attr).
#[inline(always)]
unsafe fn ensure_initialized(mutex: *mut PosixMutex) -> Result<(), u32> {
    if (*mutex).magic != STATIC_INIT_MAGIC {
        return Ok(());
    }
    match (ops().init_static)(mutex, core::ptr::null_mut()) {
        0 => Ok(()),
        status => Err(status),
    }
}

/// posix_mutex_lock — original: `FUN_082e8390` @ 0x082e8390 (72 bytes;
/// 240 call sites, binary-verified — see the module header).
///
/// Blocking acquire: initialize on first use, then hand off to the
/// deadline core with no deadline (the original's tail `b 0x080cdd6c`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn posix_mutex_lock(mutex: *mut PosixMutex) -> u32 {
    if mutex.is_null() {
        return ERR_INVALID_OBJECT;
    }
    if let Err(status) = ensure_initialized(mutex) {
        return status;
    }
    posix_mutex_lock_deadline(mutex, core::ptr::null())
}

/// posix_mutex_lock_deadline — original: `FUN_080cdd6c` @ 0x080cdd6c
/// (256 bytes; 1 call site — the lock's tail `b` @ 0x082e83d0 — binary-
/// verified).
///
/// The acquire core. `deadline` is an *absolute* time; NULL waits
/// forever. See the module header for the step-by-step algorithm.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn posix_mutex_lock_deadline(
    mutex: *mut PosixMutex,
    deadline: *const TimeSpec,
) -> u32 {
    let ops = ops();
    let kind = mutex_kind(mutex);
    let me = (ops.current_thread)();

    if (*mutex).owner == me {
        match kind {
            MutexKind::Recursive => {
                let held = (*mutex).recursion;
                if held >= RECURSION_LIMIT {
                    return ERR_RECURSION_OVERFLOW;
                }
                (*mutex).recursion = held + 1;
                return 0;
            }
            MutexKind::ErrorCheck => return ERR_WOULD_DEADLOCK,
            // Normal (and the unused kind 3) fall through and wait on a
            // semaphore this thread already holds — self-deadlock, which
            // is what the original does and what a normal mutex means.
            MutexKind::Normal | MutexKind::Reserved => {}
        }
    }

    let cell = core::ptr::addr_of_mut!((*mutex).sem_handle);
    let status = if deadline.is_null() {
        (ops.sem_acquire)(cell)
    } else {
        let mut now = TimeSpec::default();
        // A clock failure is returned raw, ahead of the result
        // register (the original branches past its `mov r0, r5`).
        let failed = (ops.clock_now)(CLOCK_WALL, &mut now);
        if failed != 0 {
            return failed;
        }
        (ops.sem_acquire_timed)(cell, &relative_wait(&*deadline, &now))
    };
    if status != 0 {
        return status;
    }

    (*mutex).owner = me;
    (*mutex).recursion = 1;
    0
}

/// Absolute deadline minus now, with a borrowed nanosecond field
/// normalized back into range (the original's `blt` loop around the
/// 1e9 literal).
#[inline(always)]
fn relative_wait(deadline: &TimeSpec, now: &TimeSpec) -> TimeSpec {
    let mut wait = TimeSpec {
        sec: deadline.sec.wrapping_sub(now.sec),
        nsec: deadline.nsec.wrapping_sub(now.nsec),
    };
    while wait.nsec < 0 {
        wait.sec = wait.sec.wrapping_sub(1);
        wait.nsec = wait.nsec.wrapping_add(NANOS_PER_SEC);
    }
    wait
}

/// posix_mutex_unlock — original: `FUN_082e83d8` @ 0x082e83d8
/// (156 bytes; 266 call sites, binary-verified — see the module header).
///
/// Release. Only the owner may unlock; a recursive mutex unwinds one
/// level at a time and only signals the semaphore on the last one.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn posix_mutex_unlock(mutex: *mut PosixMutex) -> u32 {
    if mutex.is_null() {
        return ERR_INVALID_OBJECT;
    }
    if let Err(status) = ensure_initialized(mutex) {
        return status;
    }
    let ops = ops();
    let kind = mutex_kind(mutex);
    if (*mutex).owner != (ops.current_thread)() {
        return ERR_NOT_OWNER;
    }
    if kind == MutexKind::Recursive {
        let held = (*mutex).recursion.wrapping_sub(1);
        (*mutex).recursion = held;
        if held != 0 {
            return 0;
        }
    }
    (*mutex).recursion = 0;
    (*mutex).owner = 0;
    (ops.sem_release)(core::ptr::addr_of_mut!((*mutex).sem_handle))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the tests that swap the global ops table.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev {
        Init { mutex: usize, attr: usize },
        Thread,
        Acquire(usize),
        AcquireTimed(usize, TimeSpec),
        Release(usize),
        ClockNow(u32),
    }

    static mut EVENTS: Vec<Ev> = Vec::new();

    fn events() -> Vec<Ev> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    fn record(ev: Ev) {
        unsafe { (*core::ptr::addr_of_mut!(EVENTS)).push(ev) };
    }

    // Mock knobs.
    static mut THREAD_ID: u32 = 7;
    static mut INIT_RET: u32 = 0;
    static mut INIT_WRITES_MAGIC: u32 = 0;
    static mut ACQUIRE_RET: u32 = 0;
    static mut RELEASE_RET: u32 = 0;
    static mut CLOCK_RET: u32 = 0;
    static mut CLOCK_NOW: TimeSpec = TimeSpec { sec: 0, nsec: 0 };

    unsafe extern "C" fn mock_init(mutex: *mut PosixMutex, attr: *mut u8) -> u32 {
        record(Ev::Init {
            mutex: mutex as usize,
            attr: attr as usize,
        });
        if INIT_WRITES_MAGIC != 0 {
            (*mutex).magic = INIT_WRITES_MAGIC;
        }
        INIT_RET
    }

    unsafe extern "C" fn mock_thread() -> u32 {
        record(Ev::Thread);
        THREAD_ID
    }

    unsafe extern "C" fn mock_acquire(cell: *mut u32) -> u32 {
        record(Ev::Acquire(cell as usize));
        ACQUIRE_RET
    }

    unsafe extern "C" fn mock_acquire_timed(cell: *mut u32, timeout: *const TimeSpec) -> u32 {
        record(Ev::AcquireTimed(cell as usize, *timeout));
        ACQUIRE_RET
    }

    unsafe extern "C" fn mock_release(cell: *mut u32) -> u32 {
        record(Ev::Release(cell as usize));
        RELEASE_RET
    }

    unsafe extern "C" fn mock_clock(clock_id: u32, out: *mut TimeSpec) -> u32 {
        record(Ev::ClockNow(clock_id));
        *out = CLOCK_NOW;
        CLOCK_RET
    }

    const MOCK_OPS: PosixMutexOps = PosixMutexOps {
        init_static: mock_init,
        current_thread: mock_thread,
        sem_acquire: mock_acquire,
        sem_acquire_timed: mock_acquire_timed,
        sem_release: mock_release,
        clock_now: mock_clock,
    };

    /// Installs the recording mocks and resets every knob.
    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            THREAD_ID = 7;
            INIT_RET = 0;
            INIT_WRITES_MAGIC = 0;
            ACQUIRE_RET = 0;
            RELEASE_RET = 0;
            CLOCK_RET = 0;
            CLOCK_NOW = TimeSpec::default();
            core::ptr::addr_of_mut!(POSIX_MUTEX_OPS).write(MOCK_OPS);
        }
        guard
    }

    fn restore() {
        unsafe { core::ptr::addr_of_mut!(POSIX_MUTEX_OPS).write(DEFAULT_POSIX_MUTEX_OPS) };
    }

    /// A live (already-initialized) mutex of the given kind, unheld.
    fn live(kind: MutexKind) -> PosixMutex {
        let bits: u32 = match kind {
            MutexKind::Normal => 0,
            MutexKind::ErrorCheck => 1,
            MutexKind::Recursive => 2,
            MutexKind::Reserved => 3,
        };
        PosixMutex {
            magic: 0x4d55_5458,
            owner: 0,
            reserved_08: 0,
            // Kind bits live at 4..5 of the halfword at +0xe.
            attr_flags: (bits << 4) << 16,
            reserved_10: 0,
            recursion: 0,
            sem_handle: 0x5EAA_0001,
        }
    }

    fn cell_of(m: &mut PosixMutex) -> usize {
        core::ptr::addr_of_mut!(m.sem_handle) as usize
    }

    #[test]
    fn kind_bits_cover_all_four_values() {
        for (bits, kind) in [
            (0u32, MutexKind::Normal),
            (1, MutexKind::ErrorCheck),
            (2, MutexKind::Recursive),
            (3, MutexKind::Reserved),
        ] {
            let mut m = live(MutexKind::Normal);
            // Every neighbouring bit set: only 20..21 may reach the
            // decode (the original's `lsl #26` / `lsr #30` window on the
            // halfword at +0xe).
            m.attr_flags = (!0x0030_0000u32) | (bits << 20);
            assert_eq!(unsafe { mutex_kind(&m) }, kind, "bits {bits}");
        }
    }

    #[test]
    fn null_mutex_is_rejected_by_both_halves() {
        let _guard = install();
        unsafe {
            assert_eq!(posix_mutex_lock(core::ptr::null_mut()), ERR_INVALID_OBJECT);
            assert_eq!(posix_mutex_unlock(core::ptr::null_mut()), ERR_INVALID_OBJECT);
        }
        assert!(events().is_empty(), "a NULL object reaches nothing");
        restore();
    }

    #[test]
    fn uncontended_lock_claims_the_mutex_and_unlock_releases_it() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        let cell = cell_of(&mut m);
        unsafe {
            assert_eq!(posix_mutex_lock(&mut m), 0);
            assert_eq!(m.owner, 7, "owner := the running thread");
            assert_eq!(m.recursion, 1);
            assert_eq!(events(), std::vec![Ev::Thread, Ev::Acquire(cell)]);

            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            assert_eq!(posix_mutex_unlock(&mut m), 0);
            assert_eq!(m.owner, 0, "released");
            assert_eq!(m.recursion, 0);
            assert_eq!(events(), std::vec![Ev::Thread, Ev::Release(cell)]);
        }
        restore();
    }

    /// Contended: the semaphore wait fails, so nothing is claimed and
    /// the wait's status is returned verbatim.
    #[test]
    fn a_failed_wait_leaves_the_mutex_untouched() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        m.owner = 99;
        m.recursion = 4;
        unsafe {
            ACQUIRE_RET = ERR_INVALID_OBJECT;
            assert_eq!(posix_mutex_lock(&mut m), ERR_INVALID_OBJECT);
            assert_eq!(m.owner, 99, "another thread still owns it");
            assert_eq!(m.recursion, 4);
        }
        restore();
    }

    /// Contended and then handed over: a mutex held by someone else is
    /// waited for, and the wait's success is what claims it.
    #[test]
    fn a_mutex_held_elsewhere_is_waited_for_then_claimed() {
        let _guard = install();
        let mut m = live(MutexKind::Recursive);
        m.owner = 99;
        m.recursion = 3;
        let cell = cell_of(&mut m);
        unsafe {
            assert_eq!(posix_mutex_lock(&mut m), 0);
            assert_eq!(
                events(),
                std::vec![Ev::Thread, Ev::Acquire(cell)],
                "a foreign owner never takes the recursion fast path"
            );
            assert_eq!(m.owner, 7);
            assert_eq!(m.recursion, 1, "the new holder starts at one");
        }
        restore();
    }

    #[test]
    fn a_recursive_mutex_nests_without_touching_the_semaphore() {
        let _guard = install();
        let mut m = live(MutexKind::Recursive);
        let cell = cell_of(&mut m);
        unsafe {
            assert_eq!(posix_mutex_lock(&mut m), 0);
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            assert_eq!(posix_mutex_lock(&mut m), 0);
            assert_eq!(posix_mutex_lock(&mut m), 0);
            assert_eq!(m.recursion, 3);
            assert_eq!(
                events(),
                std::vec![Ev::Thread, Ev::Thread],
                "no semaphore traffic while re-entering"
            );

            // ...and unwinds one level per unlock, signalling once.
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            assert_eq!(posix_mutex_unlock(&mut m), 0);
            assert_eq!(m.recursion, 2);
            assert_eq!(posix_mutex_unlock(&mut m), 0);
            assert_eq!(m.recursion, 1);
            assert_eq!(m.owner, 7, "still held");
            assert_eq!(posix_mutex_unlock(&mut m), 0);
            assert_eq!(m.recursion, 0);
            assert_eq!(m.owner, 0, "the last level releases");
            assert_eq!(
                events(),
                std::vec![Ev::Thread, Ev::Thread, Ev::Thread, Ev::Release(cell)],
                "exactly one signal, on the outermost unlock"
            );
        }
        restore();
    }

    #[test]
    fn a_recursive_mutex_refuses_to_overflow_its_counter() {
        let _guard = install();
        let mut m = live(MutexKind::Recursive);
        unsafe {
            m.owner = 7;
            m.recursion = RECURSION_LIMIT - 1;
            assert_eq!(posix_mutex_lock(&mut m), 0, "the last level still fits");
            assert_eq!(m.recursion, RECURSION_LIMIT);
            assert_eq!(posix_mutex_lock(&mut m), ERR_RECURSION_OVERFLOW);
            assert_eq!(m.recursion, RECURSION_LIMIT, "refused, not wrapped");
            assert!(
                !events().contains(&Ev::Acquire(cell_of(&mut m))),
                "an overflow never falls through to the semaphore"
            );
        }
        restore();
    }

    #[test]
    fn an_error_checking_mutex_reports_the_self_deadlock() {
        let _guard = install();
        let mut m = live(MutexKind::ErrorCheck);
        let cell = cell_of(&mut m);
        unsafe {
            assert_eq!(posix_mutex_lock(&mut m), 0);
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            assert_eq!(posix_mutex_lock(&mut m), ERR_WOULD_DEADLOCK);
            assert_eq!(m.recursion, 1, "the count does not move");
            assert!(!events().contains(&Ev::Acquire(cell)), "never waits");
        }
        restore();
    }

    /// A normal mutex has no owner fast path at all: re-locking goes
    /// straight back to the semaphore (which on device blocks forever).
    #[test]
    fn a_normal_mutex_re_locked_by_its_owner_waits_again() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        let cell = cell_of(&mut m);
        unsafe {
            assert_eq!(posix_mutex_lock(&mut m), 0);
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            assert_eq!(posix_mutex_lock(&mut m), 0);
            assert_eq!(
                events(),
                std::vec![Ev::Thread, Ev::Acquire(cell)],
                "self-deadlock is the documented behavior"
            );
            assert_eq!(m.recursion, 1, "reset, not incremented");
        }
        restore();
    }

    #[test]
    fn unlocking_a_mutex_owned_by_someone_else_is_refused() {
        let _guard = install();
        let mut m = live(MutexKind::Recursive);
        m.owner = 99;
        m.recursion = 2;
        unsafe {
            assert_eq!(posix_mutex_unlock(&mut m), ERR_NOT_OWNER);
            assert_eq!(m.owner, 99, "untouched");
            assert_eq!(m.recursion, 2);
            assert_eq!(events(), std::vec![Ev::Thread], "no semaphore traffic");
        }
        restore();
    }

    /// An unheld mutex has owner 0, which no live thread id matches.
    #[test]
    fn unlocking_an_unheld_mutex_is_refused() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        unsafe {
            assert_eq!(posix_mutex_unlock(&mut m), ERR_NOT_OWNER);
        }
        restore();
    }

    #[test]
    fn the_release_status_is_returned_verbatim() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        unsafe {
            posix_mutex_lock(&mut m);
            RELEASE_RET = ERR_RECURSION_OVERFLOW;
            assert_eq!(posix_mutex_unlock(&mut m), ERR_RECURSION_OVERFLOW);
            assert_eq!(m.owner, 0, "the object is released either way");
        }
        restore();
    }

    // --- lazy static initialization -------------------------------------

    #[test]
    fn a_statically_initialized_mutex_is_initialized_on_first_use() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        m.magic = STATIC_INIT_MAGIC;
        let addr = &mut m as *mut PosixMutex as usize;
        unsafe {
            INIT_WRITES_MAGIC = 0x4d55_5458;
            assert_eq!(posix_mutex_lock(&mut m), 0);
            assert_eq!(
                events().first(),
                Some(&Ev::Init { mutex: addr, attr: 0 }),
                "initialized with the default (NULL) attr, before anything else"
            );
            // Now live: a second lock does not re-initialize.
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            posix_mutex_unlock(&mut m);
            posix_mutex_lock(&mut m);
            assert!(
                !events().iter().any(|e| matches!(e, Ev::Init { .. })),
                "the magic is gone, so the initializer is not consulted again"
            );
        }
        restore();
    }

    #[test]
    fn an_initializer_failure_is_propagated_by_both_halves() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        m.magic = STATIC_INIT_MAGIC;
        unsafe {
            INIT_RET = ERR_INVALID_OBJECT;
            assert_eq!(posix_mutex_lock(&mut m), ERR_INVALID_OBJECT);
            assert_eq!(posix_mutex_unlock(&mut m), ERR_INVALID_OBJECT);
            assert_eq!(m.owner, 0, "nothing happened to the object");
            assert!(
                events().iter().all(|e| matches!(e, Ev::Init { .. })),
                "the initializer's failure short-circuits everything"
            );
        }
        restore();
    }

    // --- the deadline core ----------------------------------------------

    #[test]
    fn a_deadline_becomes_a_relative_wait() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        let cell = cell_of(&mut m);
        unsafe {
            CLOCK_NOW = TimeSpec { sec: 100, nsec: 500 };
            let deadline = TimeSpec { sec: 103, nsec: 900 };
            assert_eq!(posix_mutex_lock_deadline(&mut m, &deadline), 0);
            assert_eq!(
                events(),
                std::vec![
                    Ev::Thread,
                    Ev::ClockNow(CLOCK_WALL),
                    Ev::AcquireTimed(cell, TimeSpec { sec: 3, nsec: 400 }),
                ]
            );
            assert_eq!(m.owner, 7);
        }
        restore();
    }

    /// A nanosecond field that goes negative borrows a whole second.
    #[test]
    fn a_borrowed_nanosecond_field_is_normalized() {
        assert_eq!(
            relative_wait(
                &TimeSpec { sec: 5, nsec: 1 },
                &TimeSpec { sec: 2, nsec: 999_999_999 },
            ),
            TimeSpec { sec: 2, nsec: 2 }
        );
        // Already past: both fields go negative, the loop runs once.
        assert_eq!(
            relative_wait(&TimeSpec { sec: 0, nsec: 0 }, &TimeSpec { sec: 1, nsec: 5 }),
            TimeSpec { sec: -2, nsec: NANOS_PER_SEC - 5 }
        );
    }

    #[test]
    fn a_clock_failure_is_returned_ahead_of_the_wait() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        unsafe {
            CLOCK_RET = ERR_INVALID_OBJECT;
            let deadline = TimeSpec { sec: 1, nsec: 0 };
            assert_eq!(
                posix_mutex_lock_deadline(&mut m, &deadline),
                ERR_INVALID_OBJECT
            );
            assert_eq!(
                events(),
                std::vec![Ev::Thread, Ev::ClockNow(CLOCK_WALL)],
                "no wait is attempted"
            );
            assert_eq!(m.owner, 0);
        }
        restore();
    }

    #[test]
    fn an_expired_deadline_returns_the_waits_status() {
        let _guard = install();
        let mut m = live(MutexKind::Normal);
        unsafe {
            const ERR_TIMED_OUT: u32 = 0x40;
            ACQUIRE_RET = ERR_TIMED_OUT;
            let deadline = TimeSpec { sec: -1, nsec: 0 };
            assert_eq!(posix_mutex_lock_deadline(&mut m, &deadline), ERR_TIMED_OUT);
            assert_eq!(m.owner, 0, "a timeout claims nothing");
        }
        restore();
    }

    /// The shipped defaults: a real lock/unlock cycle with no ROM
    /// behind it — ownership and recursion are tracked, exclusion is
    /// not (the module header's contract).
    #[test]
    fn the_wired_defaults_track_ownership_without_excluding() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore();
        let mut m = live(MutexKind::Recursive);
        unsafe {
            assert_eq!(posix_mutex_lock(&mut m), 0);
            assert_eq!(m.owner, PRE_KERNEL_THREAD);
            assert_eq!(m.recursion, 1);
            assert_eq!(posix_mutex_lock(&mut m), 0, "re-entered");
            assert_eq!(m.recursion, 2);
            assert_eq!(posix_mutex_unlock(&mut m), 0);
            assert_eq!(posix_mutex_unlock(&mut m), 0);
            assert_eq!(m.owner, 0, "fully released");
            assert_eq!(posix_mutex_unlock(&mut m), ERR_NOT_OWNER);
        }
    }

    /// A zeroed object — the state every host fixture in this crate
    /// hands the pair — is a plain unheld normal mutex, not a
    /// statically-initialized one.
    #[test]
    fn a_zeroed_object_locks_and_unlocks_cleanly_on_the_defaults() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore();
        let mut m: PosixMutex = unsafe { core::mem::zeroed() };
        unsafe {
            assert_eq!(mutex_kind(&m), MutexKind::Normal);
            assert_eq!(posix_mutex_lock(&mut m), 0);
            assert_eq!(m.owner, PRE_KERNEL_THREAD);
            assert_eq!(posix_mutex_unlock(&mut m), 0);
            assert_eq!(m.owner, 0);
        }
    }
}

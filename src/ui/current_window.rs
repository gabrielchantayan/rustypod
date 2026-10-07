//! Fetching the current window from the WindowManager's active session.
//!
//! - `ui_current_window` — original: `FUN_0811e2e4` @ 0x0811e2e4
//!   (20 bytes; exactly 15 direct `bl` call sites, all unconditional,
//!   no data-word references — verified by decoding every B/BL word and
//!   scanning every word of osos.dec, so the accessor is never dispatched
//!   virtually).
//!
//! The global struct at 0x089cb2ec is the WindowManager singleton state
//! (its literal pool neighbour at 0x8148b30 is the string
//! "WindowManager"). The accessor `ui_active_session` returns its
//! field at +0x10 under the scheduler lock pair
//! 0x08148cc8/0x08148dd4; teardown at 0x08148e20 clears that field to
//! NULL. The current-window accessor answers "which window is current right now": it
//! reads the session's current-window word at +0x1c, or 0 when there is
//! no active session.
//!
//! Call-site evidence for the result being the current window object:
//! 0x0828d9b4 tests its title string byte at +0x101 against another
//! window's; 0x081ec31c makes a virtual call through its vtable slot
//! +0xd8; 0x08180ce0/0x08182ce0/0x081843d4/0x0817f7a4/0x0828e3d4 pass
//! its +0xe8 handle to the window-list lookup 0x082775f4.

/// Byte offset of the active session's current-window word
/// (`ldrne r0, [r0, #28]`).
const CURRENT_WINDOW_OFFSET: usize = 0x1c;

#[cfg(test)]
type ActiveSession = unsafe extern "C" fn() -> *mut u8;

#[cfg(test)]
extern crate std;
#[cfg(test)]
std::thread_local! {
    static ACTIVE_SESSION: core::cell::Cell<ActiveSession> =
        core::cell::Cell::new(no_active_session);
}
#[cfg(test)]
unsafe extern "C" fn no_active_session() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
static mut HOST_WINDOW_MANAGER: [u32; 5] = [0; 5];

#[inline(always)]
unsafe fn window_manager() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x089c_b2ec as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(HOST_WINDOW_MANAGER).cast::<u32>() }
}

#[cfg(test)]
static mut SESSION_LOCK: unsafe extern "C" fn() = super::scheduler_lock::scheduler_lock;
#[cfg(test)]
static mut SESSION_UNLOCK: unsafe extern "C" fn() = super::scheduler_lock::scheduler_unlock;

/// WindowManager active session — `FUN_08148b98` @ 0x08148b98.
///
/// True extent: 32 bytes (28 instruction bytes, singleton literal at
/// 0x08148bb4); the next function begins at 0x08148bb8. Verified inbound
/// BL count: 2 plain, 0 predicated. Outgoing BL count: 2 plain, 0 predicated.
/// Acquires the scheduler lock, snapshots the singleton's +0x10 target
/// pointer word, releases the lock, and returns that snapshot (including NULL).
///
/// Deliberate deviations: none on target. Host builds use a local singleton;
/// tests replace the lock pair to exercise state changes at each boundary.
///
/// # Safety
/// The WindowManager and scheduler globals must be initialized. Returning a
/// session does not extend its lifetime or retain the scheduler lock.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_active_session() -> *mut u8 {
    #[cfg(test)]
    core::ptr::read_volatile(core::ptr::addr_of!(SESSION_LOCK))();
    #[cfg(not(test))]
    super::scheduler_lock::scheduler_lock();
    let session = window_manager().add(4).read() as usize as *mut u8;
    #[cfg(test)]
    core::ptr::read_volatile(core::ptr::addr_of!(SESSION_UNLOCK))();
    #[cfg(not(test))]
    super::scheduler_lock::scheduler_unlock();
    session
}

/// ui_current_window — original: `FUN_0811e2e4` @ 0x0811e2e4 (20 bytes,
/// extent binary-verified: the sibling flag setter 0x0811e2f8 opens its
/// `push {r4, lr}` immediately after this function's `pop {r4, pc}`).
///
/// ```text
/// 0811e2e4  push   {r4, lr}
/// 0811e2e8  bl     0x08148b98        @ WindowManager active session
/// 0811e2ec  cmp    r0, #0
/// 0811e2f0  ldrne  r0, [r0, #28]     @ session->current_window (+0x1c)
/// 0811e2f4  pop    {r4, pc}
/// ```
///
/// Returns the active session's current-window pointer at +0x1c, or NULL
/// when the WindowManager reports no active session. The NULL guard is
/// unconditional (`cmp`/`ldrne`), matching all 15 plain-`bl` call sites:
/// callers such as 0x08180ce0 dereference the result without re-checking
/// only because a live session implies a non-NULL window here, while
/// 0x0828d9b4 explicitly tolerates a NULL return.
///
/// The +0x1c word is a plain 32-bit target pointer field, so the port
/// reads `u32` and widens — the same shape
/// [`crate::ui::element_reference`] uses. Host fixtures must therefore
/// live below 4 GiB (see `src/testing.rs`).
///
/// # Deliberate deviations
///
/// None. The port is statement-for-statement the original's
/// `session ? session->current_window : NULL`.
///
/// # Safety
///
/// When the active-session accessor returns non-NULL, the session must be
/// readable through offset +0x1c; the original guards nothing else.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_current_window() -> *mut u8 {
    #[cfg(test)]
    let session = ACTIVE_SESSION.with(|accessor| accessor.get()());
    #[cfg(not(test))]
    let session = ui_active_session();
    if session.is_null() {
        return core::ptr::null_mut();
    }
    session.add(CURRENT_WINDOW_OFFSET).cast::<u32>().read() as usize as *mut u8
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    /// The active-session seam and the shared slab fixture are global, so
    /// the tests serialize on one lock.
    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut STUB_SESSION: *mut u8 = ptr::null_mut();
    static mut STUB_CALLS: u32 = 0;

    static SESSION_STATE_LOCK: Mutex<()> = Mutex::new(());
    static mut LOCKED_SESSION: u32 = 0;
    static mut SESSION_PHASE: u32 = 0;

    unsafe extern "C" fn acquire_session() {
        assert_eq!(SESSION_PHASE, 0);
        SESSION_PHASE = 1;
        window_manager().add(4).write(LOCKED_SESSION);
    }

    unsafe extern "C" fn release_session() {
        assert_eq!(SESSION_PHASE, 1);
        SESSION_PHASE = 2;
        window_manager().add(4).write(0xdead_beef);
    }

    #[test]
    fn active_session_snapshots_locked_word_before_unlock() {
        let _guard = SESSION_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SESSION_LOCK = acquire_session;
            SESSION_UNLOCK = release_session;
            for expected in [0, 1, 0x089c_b300, 0xffff_ffff] {
                HOST_WINDOW_MANAGER = [0xfeed_face; 5];
                LOCKED_SESSION = expected;
                SESSION_PHASE = 0;
                assert_eq!(ui_active_session() as usize, expected as usize);
                assert_eq!(SESSION_PHASE, 2);
                assert_eq!(HOST_WINDOW_MANAGER[4], 0xdead_beef);
            }
            SESSION_LOCK = super::super::scheduler_lock::scheduler_lock;
            SESSION_UNLOCK = super::super::scheduler_lock::scheduler_unlock;
        }
    }

    unsafe extern "C" fn active_session_stub() -> *mut u8 {
        STUB_CALLS += 1;
        STUB_SESSION
    }

    /// Maps the fixture slab once per process. The port widens the `u32`
    /// current-window word into a host pointer, so the fixture window must
    /// live below 4 GiB; `None` means this host cannot supply such a
    /// mapping and the tests skip rather than crash.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::CURRENT_WINDOW, 0x2000)
                .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    /// The fixture base. Only reached once [`try_slab`] has confirmed the
    /// mapping exists, so the panic here is a programming error, not a
    /// host-capability shortfall.
    fn slab() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    /// The active-session record; its current-window word lives at +0x1c.
    unsafe fn session() -> *mut u8 {
        slab()
    }

    /// Stand-in for the current window object; only its address is
    /// observed.
    unsafe fn window() -> *mut u8 {
        slab().add(0x1000)
    }

    unsafe fn write_word(record: *mut u8, offset: usize, value: u32) {
        record.add(offset).cast::<u32>().write(value);
    }

    /// Resets every fixture word a test can observe, then installs the
    /// active-session stub returning `stub_session`.
    unsafe fn prepare(stub_session: *mut u8) {
        STUB_SESSION = stub_session;
        STUB_CALLS = 0;
        ACTIVE_SESSION.with(|accessor| accessor.set(active_session_stub));

        // Poison the words bracketing +0x1c so a test catches a port that
        // reads the wrong offset.
        write_word(session(), 0x18, 0xdead_beef);
        write_word(session(), CURRENT_WINDOW_OFFSET, window() as u32);
        write_word(session(), 0x20, 0xdead_beef);
    }

    #[test]
    fn null_session_returns_null_without_deref() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::current_window");
            return;
        }
        unsafe {
            prepare(ptr::null_mut());

            assert_eq!(ui_current_window(), ptr::null_mut());
            assert_eq!(STUB_CALLS, 1);
        }
    }

    #[test]
    fn live_session_returns_current_window_word() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::current_window");
            return;
        }
        unsafe {
            prepare(session());

            assert_eq!(ui_current_window(), window());
            assert_eq!(STUB_CALLS, 1);
        }
    }

    #[test]
    fn live_session_with_null_window_word_returns_null() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::current_window");
            return;
        }
        unsafe {
            prepare(session());
            // The original's `ldrne` loads whatever the word holds; a
            // zero current-window field must pass through as NULL.
            write_word(session(), CURRENT_WINDOW_OFFSET, 0);

            assert_eq!(ui_current_window(), ptr::null_mut());
            assert_eq!(STUB_CALLS, 1);
        }
    }
}

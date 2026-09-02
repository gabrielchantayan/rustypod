//! `class_8c00_commit_mode` — original: `default` @ `0x081a53c8`
//! (120 bytes of code per Ghidra; true extent 124, `0x081a53c8..0x081a5444`,
//! because the trailing literal-pool word @ `0x081a5440` — the app-root
//! global `0x089ca674`, reached by `ldr r0, [pc, #36]` @ `0x081a5414` —
//! belongs to it; the next function opens `push {r4, lr}` @ `0x081a5444`).
//!
//! A method of the registry-class-0x8c00 object (the singleton from
//! `app/singletons.rs`: ready bytes +0x69/+0x6a, class-0x8900 cache at
//! +0xd0, mode word at +0xd8 — the last field its ctor `FUN_081a71fc`
//! zeroes). Verified call count by decoding every B/BL word in osos.dec:
//! 27 branch sites — 23 plain `bl`, 1 predicated `blne` (@ `0x081a68cc`,
//! gated on the result of a call on the +0xd0 object), and 3 tail `b`
//! sites from sibling methods — 24 `bl` counting the predicated form.
//! Across all sites `mode` (r2) is always 1 or 2; `refresh` (r1) is 1, 4,
//! or a variable.
//!
//! ## Algorithm
//!
//! ```text
//! if (this->mode_d8 != mode) {
//!     if (mode == 1 || mode == 2) {                // others: no broadcast, no store
//!         code = (mode == 1) ? 61 : 11;            // event codes 0x3d / 0x0b
//!         if (broadcast_event(code) == 0)          // 0x0836afc0 via service @ 0x089ca458
//!             this->mode_d8 = mode;                // commit only on success (streq)
//!     }
//! }
//! if (refresh == 1) {
//!     tail = 1;
//! } else {                                         // any other refresh value, incl. 4
//!     root  = *0x089ca674;                         // app root (crate APP_ROOT_OBJECT)
//!     value = read_property_6056(root);            // 0x081115cc — arg is dead: it
//!                                                  // tail-calls vtable+0xe0 of
//!                                                  // instance_of_class_6000() with
//!                                                  // key 0x6056 / magic 0x55693332
//!     scaled = scale_value(value);                 // 0x080e676c — piecewise-linear
//!                                                  // 0..100 -> 6..55 curve over the
//!                                                  // constant getters 0x080539cc (6)
//!                                                  // and 0x08051e30 (55)
//!     item = settings_item_get();                  // 0x081533ec — cxa-guarded record
//!                                                  // @ 0x08a12700 (init: +8 = 100,
//!                                                  // +12 = 0)
//!     settings_item_store(item, scaled);           // 0x081534b8 — item+8 = scaled,
//!                                                  // notify via (*item)->vtable+0x18
//!     tail = 4;
//! }
//! return commit_global_mode(tail);                 // 0x0815968c — byte @ 0x089cc8f0 =
//!                                                  // tail, then vtable+0x20 of the
//!                                                  // guarded singleton @ 0x089cb208
//!                                                  // with (tail == 4); modes other
//!                                                  // than 1/4 are returned unchanged
//! ```
//!
//! The class-0x8c00 class is NOT named (its ctor never reaches the name
//! factory) and neither the mode word at +0xd8 nor the tail byte @
//! 0x089cc8f0 has a surviving name; the symbols name the observable
//! mechanics and nothing more.
//!
//! ## Deviations
//!
//! All six callees are unported, so they ride the
//! [`CLASS_8C00_COMMIT_SEAMS`] dispatch table (the `SINGLETON_CTORS`
//! house pattern), read slot-by-slot through `read_volatile`. The wired
//! defaults are inert but never invent behavior: the broadcast default
//! returns 11, exactly the original's service-absent path (the
//! `+4` slot of the global @ `0x089ca458` NULL → `mov r0, #11; bx lr`);
//! the settings-item store default returns 0, the original's constant
//! return; the global-mode default returns the mode unchanged, exactly
//! the original's rejection path for modes outside {1, 4}. The property
//! reader, scale and item getter defaults (0, identity, NULL) are
//! documented stubs — with them the refresh path is harmless but writes
//! nothing real, so the port is NOT hook-ready on the refresh != 1 path
//! until the settings chain is ported. The app-root word follows the
//! crate-static [`APP_ROOT_OBJECT`](crate::app::context_scope::APP_ROOT_OBJECT)
//! deviation (the image's `0x089cxxxx` page holds stale bytes).

use crate::app::context_scope::app_root_object;
use core::ptr;

/// Byte offset of the mode word the class-0x8c00 ctor zeroes last
/// (`ldr`/`str` at `[rN, #0xd8]` in the original).
const MODE_FIELD_OFFSET: usize = 0xd8;

/// Event code broadcast when committing mode 1 (`mov r0, #0x3d`).
const BROADCAST_CODE_MODE_1: u32 = 61;

/// Event code broadcast when committing mode 2 (`mov r0, #0xb`).
const BROADCAST_CODE_MODE_2: u32 = 11;

/// Tail mode when the refresh path is skipped (`moveq r0, #1`).
const TAIL_MODE_NO_REFRESH: u32 = 1;

/// Tail mode after a refresh (`mov r0, #4`).
const TAIL_MODE_REFRESHED: u32 = 4;

/// The six unported callees, one slot each, in call order.
#[derive(Copy, Clone)]
pub struct Class8c00CommitSeams {
    /// Original @ `0x0836afc0`: posts `code` through the service at the
    /// `+4` slot of the global @ `0x089ca458` (jump to its `+0x10`
    /// function pointer); returns 11 when no service is installed.
    pub broadcast_event: unsafe extern "C" fn(u32) -> u32,
    /// Original @ `0x081115cc`: reads property `0x6056` from the
    /// class-0x6000 instance. Takes the app root in r0 but never reads
    /// it — the ABI argument is kept so the signature matches.
    pub read_property_6056: unsafe extern "C" fn(*mut u8) -> u32,
    /// Original @ `0x080e676c`: piecewise-linear 0..100 → 6..55 scale.
    pub scale_value: unsafe extern "C" fn(u32) -> u32,
    /// Original @ `0x081533ec`: cxa-guarded settings record @
    /// `0x08a12700`.
    pub settings_item_get: unsafe extern "C" fn() -> *mut u8,
    /// Original @ `0x081534b8`: stores `value` at record `+8`, notifies
    /// `(*item)->vtable[+0x18]`, always returns 0.
    pub settings_item_store: unsafe extern "C" fn(*mut u8, u32) -> u32,
    /// Original @ `0x0815968c`: for mode 1 or 4 stores the mode byte @
    /// `0x089cc8f0` and notifies the guarded singleton @ `0x089cb208`
    /// (vtable `+0x20`, flag = `mode == 4`); other modes pass through.
    pub commit_global_mode: unsafe extern "C" fn(u32) -> u32,
}

/// Faithful to the original's service-absent path: the original returns
/// 11 without touching anything when the service global's `+4` slot is
/// NULL.
unsafe extern "C" fn seam_broadcast_absent(_code: u32) -> u32 {
    11
}

/// Stub: the property accessor is not ported; returns 0.
unsafe extern "C" fn seam_read_property_stub(_root: *mut u8) -> u32 {
    0
}

/// Stub: the scale is not ported; identity keeps the value in range of
/// whatever the reader stub produced.
unsafe extern "C" fn seam_scale_identity(value: u32) -> u32 {
    value
}

/// Stub: the settings record is not ported; NULL (the store default
/// below never dereferences it).
unsafe extern "C" fn seam_settings_item_absent() -> *mut u8 {
    ptr::null_mut()
}

/// Stub: writes nothing; the 0 return matches the original's constant
/// `mov r0, #0`.
unsafe extern "C" fn seam_settings_item_store_stub(_item: *mut u8, _value: u32) -> u32 {
    0
}

/// Faithful to the original's rejection path (any mode outside {1, 4}
/// is returned untouched); for 1/4 the mode-byte store and the vtable
/// notify are skipped — those targets are not ported.
unsafe extern "C" fn seam_commit_global_mode_passthrough(mode: u32) -> u32 {
    mode
}

/// Wired defaults (documented stubs; see the module header).
pub(crate) const DEFAULT_CLASS_8C00_COMMIT_SEAMS: Class8c00CommitSeams =
    Class8c00CommitSeams {
        broadcast_event: seam_broadcast_absent,
        read_property_6056: seam_read_property_stub,
        scale_value: seam_scale_identity,
        settings_item_get: seam_settings_item_absent,
        settings_item_store: seam_settings_item_store_stub,
        commit_global_mode: seam_commit_global_mode_passthrough,
    };

/// The active callees. Host tests install recording mocks; the real
/// ports replace the defaults when they exist.
pub static mut CLASS_8C00_COMMIT_SEAMS: Class8c00CommitSeams =
    DEFAULT_CLASS_8C00_COMMIT_SEAMS;

/// Reads one seam slot (volatile — same rationale as every dispatch
/// table: the slot is meant to be swapped at runtime).
macro_rules! seam {
    ($field:ident) => {
        ptr::read_volatile(ptr::addr_of!(CLASS_8C00_COMMIT_SEAMS.$field))
    };
}

/// Commits `mode` into the class-0x8c00 object's `+0xd8` word behind an
/// event broadcast, optionally refreshes the scaled settings value from
/// the class-0x6000 property, then commits the global mode.
///
/// # Safety
///
/// `this` must point at a live class-0x8c00 object (0xdc bytes,
/// word-aligned — the heap allocation the singleton ctor zeroes), or at
/// least at a writable word-aligned word at `+0xd8`. The seam slots must
/// be callable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8c00_commit_mode(
    this: *mut u8,
    refresh: u32,
    mode: u32,
) -> u32 {
    let mode_field = this.add(MODE_FIELD_OFFSET).cast::<u32>();
    if mode_field.read() != mode {
        if mode == 1 || mode == 2 {
            let code = if mode == 1 {
                BROADCAST_CODE_MODE_1
            } else {
                BROADCAST_CODE_MODE_2
            };
            if seam!(broadcast_event)(code) == 0 {
                mode_field.write(mode);
            }
        }
    }
    let tail_mode = if refresh == 1 {
        TAIL_MODE_NO_REFRESH
    } else {
        let root = app_root_object();
        let value = seam!(read_property_6056)(root);
        let scaled = seam!(scale_value)(value);
        let item = seam!(settings_item_get)();
        seam!(settings_item_store)(item, scaled);
        TAIL_MODE_REFRESHED
    };
    seam!(commit_global_mode)(tail_mode)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::context_scope::APP_ROOT_OBJECT;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the seam table or the root.
    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    /// One recorded seam invocation, in call order.
    #[derive(Debug, PartialEq, Eq, Clone)]
    enum Call {
        Broadcast(u32),
        ReadProperty(*mut u8),
        Scale(u32),
        ItemGet,
        ItemStore(*mut u8, u32),
        CommitGlobal(u32),
    }

    static mut CALLS: Vec<Call> = Vec::new();
    static mut BROADCAST_RESULT: u32 = 0;
    static mut PROPERTY_RESULT: u32 = 0;
    static mut SCALE_DELTA: u32 = 0;
    static mut ITEM: *mut u8 = ptr::null_mut();
    static mut COMMIT_RESULT: u32 = 0;

    unsafe extern "C" fn recording_broadcast(code: u32) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push(Call::Broadcast(code));
        ptr::read_volatile(ptr::addr_of!(BROADCAST_RESULT))
    }

    unsafe extern "C" fn recording_read_property(root: *mut u8) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push(Call::ReadProperty(root));
        ptr::read_volatile(ptr::addr_of!(PROPERTY_RESULT))
    }

    unsafe extern "C" fn recording_scale(value: u32) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push(Call::Scale(value));
        value.wrapping_add(ptr::read_volatile(ptr::addr_of!(SCALE_DELTA)))
    }

    unsafe extern "C" fn recording_item_get() -> *mut u8 {
        (*ptr::addr_of_mut!(CALLS)).push(Call::ItemGet);
        ptr::read_volatile(ptr::addr_of!(ITEM))
    }

    unsafe extern "C" fn recording_item_store(item: *mut u8, value: u32) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push(Call::ItemStore(item, value));
        7 // deliberately NOT the original's 0: the caller must ignore it
    }

    unsafe extern "C" fn recording_commit_global(mode: u32) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push(Call::CommitGlobal(mode));
        ptr::read_volatile(ptr::addr_of!(COMMIT_RESULT))
    }

    /// A fake root object and a fake settings record; only their
    /// addresses are observed, never their contents.
    static mut FAKE_ROOT: u32 = 0;
    static mut FAKE_ITEM: [u32; 4] = [0; 4];

    /// Installs the recording seams and clears the log. `broadcast_result`
    /// / `commit_result` select the mock return values.
    fn mock(broadcast_result: u32, commit_result: u32) -> MutexGuard<'static, ()> {
        let guard = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            CLASS_8C00_COMMIT_SEAMS = Class8c00CommitSeams {
                broadcast_event: recording_broadcast,
                read_property_6056: recording_read_property,
                scale_value: recording_scale,
                settings_item_get: recording_item_get,
                settings_item_store: recording_item_store,
                commit_global_mode: recording_commit_global,
            };
            BROADCAST_RESULT = broadcast_result;
            PROPERTY_RESULT = 0x1234;
            SCALE_DELTA = 0x10;
            ITEM = ptr::addr_of_mut!(FAKE_ITEM) as *mut u8;
            COMMIT_RESULT = commit_result;
            APP_ROOT_OBJECT = ptr::addr_of_mut!(FAKE_ROOT) as *mut u8;
            (*ptr::addr_of_mut!(CALLS)).clear();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            CLASS_8C00_COMMIT_SEAMS = DEFAULT_CLASS_8C00_COMMIT_SEAMS;
            APP_ROOT_OBJECT = ptr::null_mut();
            (*ptr::addr_of_mut!(CALLS)).clear();
        }
        drop(guard);
    }

    fn calls() -> Vec<Call> {
        unsafe { (*ptr::addr_of!(CALLS)).clone() }
    }

    /// A fake class-0x8c00 object: 0xdc bytes, mode word at +0xd8.
    struct FakeObject([u32; 0xdc / 4]);

    impl FakeObject {
        fn new(mode: u32) -> Self {
            let mut object = FakeObject([0xa5a5_a5a5; 0xdc / 4]);
            object.0[MODE_FIELD_OFFSET / 4] = mode;
            object
        }

        fn mode(&self) -> u32 {
            self.0[MODE_FIELD_OFFSET / 4]
        }

        fn as_ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr() as *mut u8
        }
    }

    #[test]
    fn mode_unchanged_neither_broadcasts_nor_stores() {
        let guard = mock(0, 0xdead);
        let mut object = FakeObject::new(1);

        let result = unsafe { class_8c00_commit_mode(object.as_ptr(), 1, 1) };

        assert_eq!(result, 0xdead, "the tail seam's return propagates");
        assert_eq!(object.mode(), 1);
        assert_eq!(
            calls(),
            [Call::CommitGlobal(TAIL_MODE_NO_REFRESH)],
            "refresh == 1 skips the refresh chain and tails with mode 1"
        );
        restore(guard);
    }

    #[test]
    fn mode_one_broadcasts_61_and_commits_on_success() {
        let guard = mock(0, 0);
        let mut object = FakeObject::new(2);

        unsafe { class_8c00_commit_mode(object.as_ptr(), 1, 1) };

        assert_eq!(object.mode(), 1, "success commits the new mode");
        assert_eq!(
            calls(),
            [Call::Broadcast(BROADCAST_CODE_MODE_1), Call::CommitGlobal(1)]
        );
        restore(guard);
    }

    #[test]
    fn mode_two_broadcasts_11_and_commits_on_success() {
        let guard = mock(0, 0);
        let mut object = FakeObject::new(1);

        unsafe { class_8c00_commit_mode(object.as_ptr(), 1, 2) };

        assert_eq!(object.mode(), 2);
        assert_eq!(
            calls(),
            [Call::Broadcast(BROADCAST_CODE_MODE_2), Call::CommitGlobal(1)]
        );
        restore(guard);
    }

    #[test]
    fn broadcast_failure_leaves_the_mode_word_untouched() {
        let guard = mock(5, 0);
        let mut object = FakeObject::new(0);

        unsafe { class_8c00_commit_mode(object.as_ptr(), 1, 1) };

        assert_eq!(object.mode(), 0, "the streq predicate keeps the old mode");
        assert_eq!(
            calls(),
            [Call::Broadcast(BROADCAST_CODE_MODE_1), Call::CommitGlobal(1)],
            "the tail commit runs even after a failed broadcast"
        );
        restore(guard);
    }

    #[test]
    fn unrecognized_mode_neither_broadcasts_nor_stores() {
        let guard = mock(0, 0);
        let mut object = FakeObject::new(1);

        unsafe { class_8c00_commit_mode(object.as_ptr(), 1, 7) };

        assert_eq!(object.mode(), 1, "modes outside {{1, 2}} never reach +0xd8");
        assert_eq!(
            calls(),
            [Call::CommitGlobal(1)],
            "the original's `bne` skips the broadcast entirely"
        );
        restore(guard);
    }

    #[test]
    fn refresh_chains_property_scale_store_and_tails_with_mode_four() {
        let guard = mock(0, 0xbeef);
        let mut object = FakeObject::new(1);
        let root = unsafe { ptr::addr_of_mut!(FAKE_ROOT) as *mut u8 };
        let item = unsafe { ptr::addr_of_mut!(FAKE_ITEM) as *mut u8 };

        let result = unsafe { class_8c00_commit_mode(object.as_ptr(), 4, 1) };

        assert_eq!(result, 0xbeef);
        assert_eq!(
            calls(),
            [
                Call::ReadProperty(root),
                Call::Scale(0x1234),
                Call::ItemGet,
                Call::ItemStore(item, 0x1234 + 0x10),
                Call::CommitGlobal(TAIL_MODE_REFRESHED),
            ],
            "root -> property -> scale -> item+8 store -> global mode 4"
        );
        restore(guard);
    }

    #[test]
    fn refresh_zero_also_takes_the_refresh_path() {
        let guard = mock(0, 0);
        let mut object = FakeObject::new(1);

        unsafe { class_8c00_commit_mode(object.as_ptr(), 0, 1) };

        let recorded = calls();
        assert_eq!(recorded.len(), 5, "any refresh != 1 refreshes");
        assert_eq!(recorded[4], Call::CommitGlobal(TAIL_MODE_REFRESHED));
        restore(guard);
    }

    #[test]
    fn refresh_runs_after_a_successful_mode_commit() {
        let guard = mock(0, 0);
        let mut object = FakeObject::new(2);

        unsafe { class_8c00_commit_mode(object.as_ptr(), 4, 1) };

        assert_eq!(object.mode(), 1);
        let recorded = calls();
        assert_eq!(recorded[0], Call::Broadcast(BROADCAST_CODE_MODE_1));
        assert_eq!(recorded[5], Call::CommitGlobal(TAIL_MODE_REFRESHED));
        restore(guard);
    }

    #[test]
    fn wired_defaults_are_inert_and_safe() {
        let guard = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { APP_ROOT_OBJECT = ptr::null_mut() };
        let mut object = FakeObject::new(0);

        // Broadcast default reports the service-absent 11, so +0xd8 is
        // never committed; the tail passthrough returns the mode.
        let result = unsafe { class_8c00_commit_mode(object.as_ptr(), 1, 1) };
        assert_eq!(object.mode(), 0, "absent service blocks the commit");
        assert_eq!(result, TAIL_MODE_NO_REFRESH);

        // The refresh path with stub seams touches nothing and is safe.
        let result = unsafe { class_8c00_commit_mode(object.as_ptr(), 4, 1) };
        assert_eq!(result, TAIL_MODE_REFRESHED);
        restore(guard);
    }
}

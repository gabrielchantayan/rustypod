//! `update_dispatch` — original: `FUN_082199bc` @ **0x082199bc**
//! (80 bytes of code per Ghidra + one trailing literal-pool word @
//! `0x08219a0c` = **84 bytes** of true extent, `0x082199bc..0x08219a10`;
//! the next function opens `push {r0-r4, r5, r6, r7, r8, r9, sl, fp,
//! lr}` — `e92d4fff` — @ `0x08219a10`. The dropped pool word is the
//! app-root global `0x089ca674`, reached by `ldr r0, [pc, #36]` @
//! `0x082199e0`). **23 `bl` call sites, all unconditional — 0
//! predicated, 0 plain `b`** — binary-verified by decoding every B/BL
//! word in `work/firmware/osos.dec` (Ghidra's 23 confirmed). Callers
//! sit in the Silver UI region (0x08131380's method twice, plus
//! 0x08222xxx..0x0823axxx) and all test the result (`cmp r0, #0` then
//! predicated follow-up work): **1 means "declined — nothing was
//! dispatched, the caller proceeds with its own handling", 0 means
//! "handled"**.
//!
//! ```text
//! 082199bc  push {r4, lr}
//! 082199c0  bl   0x0811b2c0        @ object = singleton_class_6280()
//! 082199c4  mov  r4, r0
//! 082199c8  bl   0x0811c564        @ flag_2c_is_clear(object)  (arg kept in r0)
//! 082199cc  cmp  r0, #0
//! 082199d0  beq  0x082199e0
//! 082199d4  mov  r0, r4            @ flag byte SET path:
//! 082199d8  bl   0x0811bf0c        @   class_6280_commit(object)
//! 082199dc  b    0x08219a04        @   return 0
//! 082199e0  ldr  r0, [pc, #36]     @ = 0x089ca674 (pool @ 0x08219a0c)
//! 082199e4  ldr  r4, [r0]          @ root = app root
//! 082199e8  mov  r0, r4
//! 082199ec  bl   0x081115e4        @ query = root_slot_190_query(root)
//! 082199f0  cmp  r0, #0
//! 082199f4  moveq r0, #1           @ query == 0 -> return 1 (declined)
//! 082199f8  popeq {r4, pc}
//! 082199fc  mov  r0, r4
//! 08219a00  bl   0x08112bbc        @ root_pending_process(root)
//! 08219a04  mov  r0, #0            @ handled
//! 08219a08  pop  {r4, pc}
//! 08219a0c  .word 0x089ca674
//! ```
//!
//! Algorithm: fetch the registry-class-**0x6280** singleton
//! (`app/singletons.rs`), then test its mode flag byte at `+0x2c`
//! (`ui/flag_2c.rs`). When the flag is non-zero the object-side handler
//! `FUN_0811bf0c` runs — per its decompilation it broadcasts the
//! class's own event family (codes **0x6280 / 0x6282 / 0x6283 / 0x6287
//! / 0x6288**, pool literals @ `0x0811bff8..0x0811c00c`) through the
//! vtable `+0x58` poster and writes **2** back into the `+0x2c` flag
//! byte — and the function returns 0. When the flag is clear the app
//! root is consulted instead: `FUN_081115e4` is a four-instruction
//! tail-call veneer (`ldr r0, [r0, #0x888]; ldr r1, [r0]; ldr r1,
//! [r1, #0x190]; bx r1`) invoking vtable slot `+0x190` of the root's
//! `+0x888` sub-object — Ghidra's C wrongly types it `void` and drops
//! the argument; the caller both passes the root in r0 and tests r0 on
//! return. A zero query result declines (return 1); otherwise
//! `FUN_08112bbc` runs (it re-queries through the same veneer, calls
//! vtable slot `+0xf0` of the same sub-object, then works the
//! `singleton_class_8c00 + 0x98` list under the `mutex_lock` /
//! `mutex_unlock` pair) and the function returns 0.
//!
//! `singleton_class_6280()` runs unconditionally, BEFORE the flag
//! test — the singleton is therefore allocated/cached even on the
//! root-only path — and neither the singleton result nor the app root
//! is NULL-checked (matching the stock `bl` chain; all 23 call sites
//! are unpredicated, so no caller gates the call either).
//!
//! ## Deviations
//!
//! The two queried callees are ported and called directly
//! ([`singleton_class_6280`], [`flag_2c_is_clear`]). The three handler
//! callees are unported and ride [`UPDATE_DISPATCH_OPS`] (the
//! `EVENT_HUB_OPS` / `IAP_THREAD_SLOT_POLL_OPS` house pattern), read
//! slot-by-slot through `read_volatile`: on target the defaults
//! transmute the ROM addresses `0x0811bf0c` / `0x081115e4` /
//! `0x08112bbc`, so a hooked build is faithful; on host the defaults
//! are documented inert stubs (commit/process no-ops, query returns 0
//! → decline), making the default port a harmless no-op that returns
//! 1. The app-root word follows the crate-static
//! [`APP_ROOT_OBJECT`](crate::app::context_scope::APP_ROOT_OBJECT)
//! deviation (the `0x089cxxxx` page is runtime-initialized RW data and
//! the image holds stale UI string bytes there).

use crate::app::context_scope::app_root_object;
use crate::app::singletons::singleton_class_6280;
use crate::ui::flag_2c::flag_2c_is_clear;
use core::ptr;

/// Firmware load addresses of the three unported handler callees, kept
/// beside the transmutes below.
pub const CLASS_6280_COMMIT_ADDRESS: usize = 0x0811_bf0c;
pub const ROOT_SLOT_190_QUERY_ADDRESS: usize = 0x0811_15e4;
pub const ROOT_PENDING_PROCESS_ADDRESS: usize = 0x0811_2bbc;

/// The three unported handler callees, one slot each, in call order.
/// Host tests install recording models; the real ports replace the
/// defaults when they land.
#[derive(Clone, Copy)]
pub struct UpdateDispatchOps {
    /// Original @ `0x0811bf0c`: the class-0x6280 object-side handler,
    /// run only when the singleton's `+0x2c` flag byte is non-zero.
    /// Broadcasts event codes 0x6280/0x6282/0x6283/0x6287/0x6288
    /// through the vtable `+0x58` poster and stores 2 into the `+0x2c`
    /// flag byte.
    pub class_6280_commit: unsafe extern "C" fn(object: *mut u8),
    /// Original @ `0x081115e4`: tail-call veneer into vtable slot
    /// `+0x190` of the app root's `+0x888` sub-object. Ghidra types it
    /// `void` and drops its argument; the original caller passes the
    /// root and tests the returned r0 against zero.
    pub root_slot_190_query: unsafe extern "C" fn(root: *mut u8) -> u32,
    /// Original @ `0x08112bbc`: the root-side handler, run only when
    /// the slot-`+0x190` query returned non-zero. Re-queries through
    /// the same veneer, calls vtable slot `+0xf0` of the `+0x888`
    /// sub-object, then processes the `singleton_class_8c00 + 0x98`
    /// list under mutex.
    pub root_pending_process: unsafe extern "C" fn(root: *mut u8),
}

/// Target default: the ROM class-0x6280 handler.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_class_6280_commit(object: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(CLASS_6280_COMMIT_ADDRESS);
    f(object)
}

/// Host default: inert — the tests install their own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_class_6280_commit(_object: *mut u8) {}

/// Target default: the ROM slot-`+0x190` query veneer.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_root_slot_190_query(root: *mut u8) -> u32 {
    let f: unsafe extern "C" fn(*mut u8) -> u32 =
        core::mem::transmute(ROOT_SLOT_190_QUERY_ADDRESS);
    f(root)
}

/// Host default: reports "nothing pending", so the port declines
/// (returns 1) without touching the root.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_root_slot_190_query(_root: *mut u8) -> u32 {
    0
}

/// Target default: the ROM root-side handler.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_root_pending_process(root: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(ROOT_PENDING_PROCESS_ADDRESS);
    f(root)
}

/// Host default: inert — unreachable anyway behind the query default's
/// constant 0.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_root_pending_process(_root: *mut u8) {}

/// Wired defaults: the ROM addresses on target, documented inert stubs
/// on host.
pub const DEFAULT_UPDATE_DISPATCH_OPS: UpdateDispatchOps = UpdateDispatchOps {
    class_6280_commit: firmware_class_6280_commit,
    root_slot_190_query: firmware_root_slot_190_query,
    root_pending_process: firmware_root_pending_process,
};

/// The active handler set. Host tests swap in recording mocks and
/// restore; the real ports replace the defaults when they exist.
pub static mut UPDATE_DISPATCH_OPS: UpdateDispatchOps = DEFAULT_UPDATE_DISPATCH_OPS;

/// Reads one seam slot (volatile — same rationale as every dispatch
/// table: the slot is meant to be swapped at runtime and LLVM must not
/// fold the indirect call to the default).
macro_rules! seam {
    ($field:ident) => {
        ptr::read_volatile(ptr::addr_of!(UPDATE_DISPATCH_OPS.$field))
    };
}

/// update_dispatch — original: `FUN_082199bc` @ 0x082199bc (see the
/// module header for the full listing, extent correction and call-count
/// verification).
///
/// Dispatches to the class-0x6280 singleton's handler when its `+0x2c`
/// flag byte is set, else to the app root's handler when the root's
/// slot-`+0x190` query reports pending work. Returns 1 when nothing
/// was dispatched (the caller then proceeds with its own handling) and
/// 0 when either handler ran.
///
/// # Safety
///
/// The class-0x6280 singleton — allocated on first call, exactly like
/// the original's unconditional leading `bl 0x0811b2c0` — must expose a
/// readable byte at `+0x2c`, and [`APP_ROOT_OBJECT`] must name a live
/// root object whenever the flag is clear; neither is NULL-checked,
/// matching the stock code. The seam slots must be callable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn update_dispatch() -> u32 {
    let object = singleton_class_6280();
    if flag_2c_is_clear(object) == 0 {
        seam!(class_6280_commit)(object);
        return 0;
    }
    let root = app_root_object();
    if seam!(root_slot_190_query)(root) == 0 {
        return 1;
    }
    seam!(root_pending_process)(root);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::context_scope::APP_ROOT_OBJECT;
    use crate::app::singletons::CLASS_6280_INSTANCE;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the seam table, the singleton
    /// cache or the app root.
    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    /// Class-0x6280 allocation size (the singleton getter's
    /// `mov r0, #0xa0`); the fake object only needs the flag byte at
    /// `+0x2c`, but matching the real size keeps the fixture honest.
    const CLASS_6280_SIZE: usize = 0xa0;

    /// Byte offset of the mode flag the dispatcher tests.
    const FLAG_OFFSET: usize = 0x2c;

    /// Recorded seam invocations, in call order.
    static mut CALLS: Vec<&'static str> = Vec::new();

    /// The object pointers the recording seams observed.
    static mut SEEN_OBJECT: *mut u8 = ptr::null_mut();
    static mut SEEN_ROOT: *mut u8 = ptr::null_mut();

    #[repr(align(4))]
    struct FakeClass6280([u8; CLASS_6280_SIZE]);

    #[repr(align(4))]
    struct FakeRoot([u8; 4]);

    static mut FAKE_OBJECT: FakeClass6280 = FakeClass6280([0; CLASS_6280_SIZE]);
    static mut FAKE_ROOT: FakeRoot = FakeRoot([0; 4]);

    unsafe extern "C" fn recording_commit(object: *mut u8) {
        (*ptr::addr_of_mut!(CALLS)).push("commit");
        SEEN_OBJECT = object;
    }

    unsafe extern "C" fn recording_query_decline(_root: *mut u8) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push("query");
        0
    }

    unsafe extern "C" fn recording_query_pending(root: *mut u8) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push("query");
        SEEN_ROOT = root;
        1
    }

    unsafe extern "C" fn recording_process(root: *mut u8) {
        (*ptr::addr_of_mut!(CALLS)).push("process");
        SEEN_ROOT = root;
    }

    /// Installs the recording seams and points the singleton cache and
    /// the app root at the fixtures; `flag` is planted at `+0x2c` of
    /// the fake class-0x6280 object.
    fn install(flag: u8, query: unsafe extern "C" fn(*mut u8) -> u32) -> MutexGuard<'static, ()> {
        let guard = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            UPDATE_DISPATCH_OPS = UpdateDispatchOps {
                class_6280_commit: recording_commit,
                root_slot_190_query: query,
                root_pending_process: recording_process,
            };
            FAKE_OBJECT.0 = [0; CLASS_6280_SIZE];
            FAKE_OBJECT.0[FLAG_OFFSET] = flag;
            CLASS_6280_INSTANCE = ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8;
            APP_ROOT_OBJECT = ptr::addr_of_mut!(FAKE_ROOT) as *mut u8;
            (*ptr::addr_of_mut!(CALLS)).clear();
            SEEN_OBJECT = ptr::null_mut();
            SEEN_ROOT = ptr::null_mut();
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            UPDATE_DISPATCH_OPS = DEFAULT_UPDATE_DISPATCH_OPS;
            CLASS_6280_INSTANCE = ptr::null_mut();
            APP_ROOT_OBJECT = ptr::null_mut();
            (*ptr::addr_of_mut!(CALLS)).clear();
        }
        drop(guard);
    }

    #[test]
    fn set_flag_runs_class_6280_commit_and_returns_handled() {
        for flag in [1u8, 2, 3, 0x7f, 0x80, 0xff] {
            let guard = install(flag, recording_query_decline);
            let result = unsafe { update_dispatch() };
            assert_eq!(result, 0, "flag={flag:#04x}");
            assert_eq!(unsafe { &*ptr::addr_of!(CALLS) }, &["commit"], "flag={flag:#04x}");
            assert_eq!(
                unsafe { ptr::read_volatile(ptr::addr_of!(SEEN_OBJECT)) },
                ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8,
                "the commit handler receives the singleton, flag={flag:#04x}"
            );
            restore(guard);
        }
    }

    #[test]
    fn clear_flag_and_empty_query_declines() {
        let guard = install(0, recording_query_decline);
        let result = unsafe { update_dispatch() };
        assert_eq!(result, 1);
        assert_eq!(unsafe { &*ptr::addr_of!(CALLS) }, &["query"]);
        restore(guard);
    }

    #[test]
    fn clear_flag_and_pending_query_runs_root_process() {
        let guard = install(0, recording_query_pending);
        let result = unsafe { update_dispatch() };
        assert_eq!(result, 0);
        assert_eq!(unsafe { &*ptr::addr_of!(CALLS) }, &["query", "process"]);
        assert_eq!(
            unsafe { ptr::read_volatile(ptr::addr_of!(SEEN_ROOT)) },
            ptr::addr_of_mut!(FAKE_ROOT) as *mut u8,
            "the root handler receives the app root, not the singleton"
        );
        restore(guard);
    }

    #[test]
    fn default_seams_are_inert_and_decline() {
        let guard = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            UPDATE_DISPATCH_OPS = DEFAULT_UPDATE_DISPATCH_OPS;
            FAKE_OBJECT.0 = [0; CLASS_6280_SIZE];
            CLASS_6280_INSTANCE = ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8;
            APP_ROOT_OBJECT = 0x1 as *mut u8; // would fault if dereferenced
            (*ptr::addr_of_mut!(CALLS)).clear();
            assert_eq!(update_dispatch(), 1);
            assert!((*ptr::addr_of!(CALLS)).is_empty());
        }
        restore(guard);
    }
}

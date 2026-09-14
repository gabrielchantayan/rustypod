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
//! The directly queried callees are ported and called directly
//! ([`singleton_class_6280`], [`flag_2c_is_clear`], and
//! [`root_slot_190_query`](crate::app::root_slot_190_query::root_slot_190_query)).
//! The class-0x6280 handler remains in [`UPDATE_DISPATCH_OPS`] and is read
//! through `read_volatile`; on target its default transmutes ROM address
//! `0x0811bf0c`, while its documented inert host default makes the dispatcher
//! decline with return 1. The app-root word follows the crate-static
//! [`APP_ROOT_OBJECT`](crate::app::context_scope::APP_ROOT_OBJECT)
//! deviation (the `0x089cxxxx` page is runtime-initialized RW data and
//! the image holds stale UI string bytes there).

use crate::app::context_scope::app_root_object;
use crate::app::root_pending_process::root_pending_process;
use crate::app::root_slot_190_query::{root_slot_190_query, RootSlot190QueryRoot};
use crate::app::singletons::singleton_class_6280;
use crate::ui::flag_2c::flag_2c_is_clear;
use core::ptr;

/// Firmware load address of the remaining unported class-0x6280 handler.
/// `root_pending_process` at 0x08112bbc and `root_slot_190_query` at
/// 0x081115e4 are ported directly in their respective modules.
pub const CLASS_6280_COMMIT_ADDRESS: usize = 0x0811_bf0c;

/// The remaining unported handler. Host tests install a recording model. The
/// root query veneer and pending-work processor are called directly.
#[derive(Clone, Copy)]
pub struct UpdateDispatchOps {
    /// Original @ `0x0811bf0c`: the class-0x6280 object-side handler,
    /// run only when the singleton's `+0x2c` flag byte is non-zero.
    /// Broadcasts event codes 0x6280/0x6282/0x6283/0x6287/0x6288
    /// through the vtable `+0x58` poster and stores 2 into the `+0x2c`
    /// flag byte.
    pub class_6280_commit: unsafe extern "C" fn(object: *mut u8),
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




/// Wired default: ROM address on target, documented inert stub on host.
pub const DEFAULT_UPDATE_DISPATCH_OPS: UpdateDispatchOps = UpdateDispatchOps {
    class_6280_commit: firmware_class_6280_commit,
};

/// The active handler set. Host tests swap in recording mocks and restore.
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
/// The class-0x6280 singleton — allocated on first call, exactly like the
/// original's unconditional leading `bl 0x0811b2c0` — must expose a readable
/// byte at `+0x2c`, and [`APP_ROOT_OBJECT`] must name a live root object
/// whenever the flag is clear; neither is NULL-checked, matching the stock
/// code. The class-handler seam must be callable, and the root must satisfy
/// [`root_slot_190_query`]'s safety contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn update_dispatch() -> u32 {
    let object = singleton_class_6280();
    if flag_2c_is_clear(object) == 0 {
        seam!(class_6280_commit)(object);
        return 0;
    }
    let root = app_root_object();
    if unsafe { root_slot_190_query(root.cast::<RootSlot190QueryRoot>()) } == 0 {
        return 1;
    }
    unsafe { root_pending_process(root.cast()) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::context_scope::APP_ROOT_OBJECT;
    use crate::app::root_pending_process::{
        RootPendingProcessCallback, RootPendingProcessRoot, RootPendingProcessSubobject,
        ROOT_PENDING_PROCESS_SLOT, ROOT_PENDING_SUBOBJECT_OFFSET,
    };
    use crate::app::root_slot_190_query::{
        RootSlot190QueryCallback, RootSlot190QuerySubobject, ROOT_SLOT_190_QUERY_SLOT,
    };
    use crate::app::singletons::{CLASS_6280_INSTANCE, CLASS_8C00_INSTANCE};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the seam table, the singleton
    /// cache or the app root.
    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    /// Class-0x6280 allocation size (the singleton getter's
    /// `mov r0, #0xa0`); the fake object only needs the flag byte at
    /// `+0x2c`, but matching the real size keeps the fixture honest.
    const CLASS_6280_SIZE: usize = 0xa0;

    /// Class-0x8c00 allocation size, matching its singleton getter's
    /// `mov r0, #0xdc`. The pending path suppresses its queue post.
    const CLASS_8C00_SIZE: usize = 0xdc;
    const CLASS_8C00_POST_SUPPRESS_OFFSET: usize = 0xcc;

    /// Byte offset of the mode flag the dispatcher tests.
    const FLAG_OFFSET: usize = 0x2c;

    /// Recorded seam invocations, in call order.
    static mut CALLS: Vec<&'static str> = Vec::new();

    /// The object pointers the recording seam and vtables observed.
    static mut SEEN_OBJECT: *mut u8 = ptr::null_mut();
    static mut SEEN_QUERY_SUBOBJECT: *mut RootSlot190QuerySubobject = ptr::null_mut();
    static mut SEEN_SUBOBJECT: *mut RootPendingProcessSubobject = ptr::null_mut();

    #[repr(align(4))]
    struct FakeClass6280([u8; CLASS_6280_SIZE]);

    #[repr(align(4))]
    struct FakeClass8c00([u8; CLASS_8C00_SIZE]);

    static mut FAKE_OBJECT: FakeClass6280 = FakeClass6280([0; CLASS_6280_SIZE]);
    static mut FAKE_ROOT: RootPendingProcessRoot = RootPendingProcessRoot {
        unresolved_000_887: [0; ROOT_PENDING_SUBOBJECT_OFFSET / 4],
        pending_subobject: ptr::null_mut(),
    };
    static mut FAKE_SUBOBJECT: RootPendingProcessSubobject = RootPendingProcessSubobject {
        vtable: ptr::null(),
    };
    static mut ROOT_VTABLE: [usize; ROOT_SLOT_190_QUERY_SLOT + 1] =
        [0; ROOT_SLOT_190_QUERY_SLOT + 1];
    static mut FAKE_CLASS_8C00: FakeClass8c00 = FakeClass8c00([0; CLASS_8C00_SIZE]);

    unsafe extern "C" fn recording_commit(object: *mut u8) {
        (*ptr::addr_of_mut!(CALLS)).push("commit");
        SEEN_OBJECT = object;
    }

    unsafe extern "C" fn recording_query_decline(subobject: *mut RootSlot190QuerySubobject) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push("query");
        SEEN_QUERY_SUBOBJECT = subobject;
        0
    }

    unsafe extern "C" fn recording_query_pending(subobject: *mut RootSlot190QuerySubobject) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push("query");
        SEEN_QUERY_SUBOBJECT = subobject;
        1
    }

    unsafe extern "C" fn recording_subobject_process(subobject: *mut RootPendingProcessSubobject) {
        (*ptr::addr_of_mut!(CALLS)).push("vtable");
        SEEN_SUBOBJECT = subobject;
    }

    /// Installs the recording seams and points the singleton cache and
    /// the app root at the fixtures; `flag` is planted at `+0x2c` of
    /// the fake class-0x6280 object.
    fn install(flag: u8, query: RootSlot190QueryCallback) -> MutexGuard<'static, ()> {
        let guard = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            UPDATE_DISPATCH_OPS = UpdateDispatchOps {
                class_6280_commit: recording_commit,
            };
            FAKE_OBJECT.0 = [0; CLASS_6280_SIZE];
            FAKE_OBJECT.0[FLAG_OFFSET] = flag;
            ROOT_VTABLE[ROOT_PENDING_PROCESS_SLOT] = recording_subobject_process as usize;
            ROOT_VTABLE[ROOT_SLOT_190_QUERY_SLOT] = query as usize;
            FAKE_SUBOBJECT.vtable = ptr::addr_of!(ROOT_VTABLE).cast();
            FAKE_ROOT.pending_subobject = ptr::addr_of_mut!(FAKE_SUBOBJECT);
            FAKE_CLASS_8C00.0 = [0; CLASS_8C00_SIZE];
            FAKE_CLASS_8C00.0[CLASS_8C00_POST_SUPPRESS_OFFSET] = 1;
            CLASS_6280_INSTANCE = ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8;
            CLASS_8C00_INSTANCE = ptr::addr_of_mut!(FAKE_CLASS_8C00) as *mut u8;
            APP_ROOT_OBJECT = ptr::addr_of_mut!(FAKE_ROOT) as *mut u8;
            (*ptr::addr_of_mut!(CALLS)).clear();
            SEEN_OBJECT = ptr::null_mut();
            SEEN_QUERY_SUBOBJECT = ptr::null_mut();
            SEEN_SUBOBJECT = ptr::null_mut();
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            UPDATE_DISPATCH_OPS = DEFAULT_UPDATE_DISPATCH_OPS;
            CLASS_6280_INSTANCE = ptr::null_mut();
            CLASS_8C00_INSTANCE = ptr::null_mut();
            APP_ROOT_OBJECT = ptr::null_mut();
            FAKE_ROOT.pending_subobject = ptr::null_mut();
            ROOT_VTABLE = [0; ROOT_SLOT_190_QUERY_SLOT + 1];
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
    fn root_process_calls_vtable_after_a_zero_requery() {
        let guard = install(0, recording_query_decline);
        unsafe { root_pending_process(ptr::addr_of_mut!(FAKE_ROOT)) };
        assert_eq!(unsafe { &*ptr::addr_of!(CALLS) }, &["query", "vtable"]);
        assert_eq!(
            unsafe { ptr::read_volatile(ptr::addr_of!(SEEN_QUERY_SUBOBJECT)) },
            ptr::addr_of_mut!(FAKE_SUBOBJECT).cast()
        );
        assert_eq!(
            unsafe { ptr::read_volatile(ptr::addr_of!(SEEN_SUBOBJECT)) },
            ptr::addr_of_mut!(FAKE_SUBOBJECT)
        );
        restore(guard);
    }

    #[test]
    fn clear_flag_and_pending_query_requeries_then_runs_root_vtable() {
        let guard = install(0, recording_query_pending);
        let result = unsafe { update_dispatch() };
        assert_eq!(result, 0);
        assert_eq!(unsafe { &*ptr::addr_of!(CALLS) }, &["query", "query", "vtable"]);
        assert_eq!(
            unsafe { ptr::read_volatile(ptr::addr_of!(SEEN_QUERY_SUBOBJECT)) },
            ptr::addr_of_mut!(FAKE_SUBOBJECT).cast(),
            "both queries receive the root's pending-work sub-object"
        );
        assert_eq!(
            unsafe { ptr::read_volatile(ptr::addr_of!(SEEN_SUBOBJECT)) },
            ptr::addr_of_mut!(FAKE_SUBOBJECT)
        );
        restore(guard);
    }

}

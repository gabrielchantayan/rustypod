//! Demo-mode calendar record fetch: `FUN_08284e4c` @ 0x08284e4c.
//!
//! # Raw extent and call sites
//!
//! The executable extent is exactly **44 bytes**
//! (`0x08284e4c..0x08284e78`): eleven instructions ending `b
//! 0x08037db0`, with the two-word literal pool at 0x08284e78 =
//! 0x000080aa (the resource id) and 0x08284e7c = 0x4474546d (the
//! kind), for a true extent of 52 bytes ending where the next function
//! opens with `push {r0, r1, r2, r3, r4, lr}` @ 0x08284e80.
//! functions.csv's 44 is the code size and is exact.
//!
//! Decoding every ARM B/BL word in `work/firmware/osos.dec` (load base
//! 0x08000000) finds **17 call sites: 16 unconditional `bl` plus one
//! `bleq` @ 0x08203a1c**. The predicated site is caller-side gating,
//! not a callee contract: `ldrb r0,[r4,#24]; cmp r0,#0; addeq
//! r0,r4,#26; bleq 0x08284e4c` fills the object's 10-byte field at
//! +0x1a only when its flag byte at +0x18 is clear. No DATA word in
//! the image holds 0x08284e4c (binary-scanned), so the function is
//! never dispatched virtually.
//!
//! # Algorithm
//!
//! ```text
//! 08284e4c  push {r4, lr}
//! 08284e50  mov  r4, r0            @ out
//! 08284e54  bl   0x081883fc        @ demo_mode_instance()
//! 08284e58  ldr  r2, =0x000080aa   @ resource id
//! 08284e5c  ldr  r1, =0x4474546d   @ kind "DtTm"
//! 08284e60  bl   0x0827216c        @ resource_chain_find
//! 08284e64  mov  r1, r0            @ record
//! 08284e68  mov  r0, r4
//! 08284e6c  pop  {r4, lr}
//! 08284e70  mov  r2, #10
//! 08284e74  b    0x08037db0        @ __rt_memcpy(out, record, 10)
//! ```
//!
//! Resolves the registered `TCDemoMode` singleton through the ported
//! [`demo_mode_instance`] @ 0x081883fc (app/registry.rs), asks its
//! resource-provider chain for the resource (kind `"DtTm"`, id
//! 0x80aa) through the ported [`resource_chain_find`] @ 0x0827216c
//! (app/resource_chain.rs), and copies the answered ten bytes into the
//! caller's buffer through the ported [`__rt_memcpy`] veneer target
//! (thunk 0x08037db0 -> ROM 0x22000020 == osos 0x08000020,
//! libc/rt_memcpy.rs). The tail `b` propagates `__rt_memcpy`'s return,
//! so the original leaves `out` in r0; the port returns it likewise.
//!
//! The ten bytes are the retailOS packed calendar record —
//! [`DateTime`]: +0 second, +1 minute, +2 hour, +3 day, +4 month,
//! +6 u16 year, +8 weekday (see time/datetime.rs). The callers pin
//! this down: `FUN_082851d0` @ 0x082851d0 round-trips the buffer
//! through `datetime_to_unix_seconds` @ 0x08093c38 and
//! `unix_seconds_to_datetime` @ 0x080964cc (both ported, both take the
//! ten-byte record), and `FUN_082ca58c` @ 0x082ca58c fills two
//! adjacent fields at +0x08 and +0x12 — a 10-byte stride. So this is
//! "copy the demo mode's fixed date/time stamp into `out`", the
//! canned clock face the demo/retail mode shows.
//!
//! # Deliberate deviations
//!
//! - All three callees are ported and called directly — no dispatch
//!   seam (the class6000_ui32_resource_60a4 precedent in
//!   fp/fp_misc.rs).
//! - The original has **no NULL guard**: when the singleton is
//!   unregistered or no provider owns the entry, [`resource_chain_find`]
//!   returns NULL and the original copies ten bytes from address 0.
//!   The port keeps that exactly — no guard, no special case.
//! - The saved r4 is a genuine frame (it carries `out` across both
//!   calls); the port holds it in a local instead.

use crate::app::registry::demo_mode_instance;
use crate::app::resource_chain::{resource_chain_find, ResourceKind, ResourceProvider};
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::time::datetime::DateTime;

/// Resource kind literal @ 0x08284e7c: 0x4474546d, `"DtTm"` read
/// big-endian — a fourth provider-chain kind beside
/// [`ResourceKind::STRING`], [`ResourceKind::BITMAP`] and the `"Ui32"`
/// of fp/fp_misc.rs. Kept local to this module rather than added to
/// app/resource_chain.rs: this port is its first decoded consumer
/// (the fp_misc.rs RESOURCE_KIND_UI32 precedent).
const RESOURCE_KIND_DTTM: ResourceKind = ResourceKind(0x4474_546d);

/// Resource id literal @ 0x08284e78: the `"DtTm"` entry holding the
/// demo mode's canned calendar record.
const RESOURCE_ID_DEMO_MODE_DATETIME: u32 = 0x80aa;

/// demo_mode_datetime — original: `FUN_08284e4c` @ 0x08284e4c
/// (**44 bytes of code, 0x08284e4c..0x08284e78, plus an 8-byte literal
/// pool through 0x08284e80; 17 call sites — 16 `bl` + 1 `bleq`,
/// binary-scanned**).
///
/// Copies the demo mode's canned calendar record — the `TCDemoMode`
/// provider chain's resource (kind `"DtTm"`, id 0x80aa) — into `out`,
/// and returns `out` (the original tail-branches to `__rt_memcpy`,
/// whose r0 it propagates). No NULL guard: a missing singleton or an
/// unanswered entry copies ten bytes from address 0, as the original.
///
/// # Safety
///
/// `out` must point at a writable ten-byte [`DateTime`]. The
/// registered demo-mode object must head a valid
/// [`ResourceProvider`] chain, as on target.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn demo_mode_datetime(out: *mut DateTime) -> *mut DateTime {
    let head = demo_mode_instance() as *mut ResourceProvider;
    let record = resource_chain_find(head, RESOURCE_KIND_DTTM, RESOURCE_ID_DEMO_MODE_DATETIME);
    __rt_memcpy(out as *mut u8, record as *const u8, core::mem::size_of::<DateTime>());
    out
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::registry::{
        FrameworkObject, Registry, RegistryEntry, RegistryVtable, CLASS_REGISTRY,
    };
    use crate::app::resource_chain::{ResourceFindFn, ResourceReadFn, ResourceWriteFn};
    use crate::testing::CLASS_REGISTRY_TEST_LOCK;
    use core::ptr;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// The fixture record the fake provider answers with — ten
    /// distinct bytes so a short or shifted copy cannot pass:
    /// 2009-09-05 21:07:03, weekday 6, both padding bytes marked.
    static DEMO_RECORD: DateTime = DateTime {
        second: 3,
        minute: 7,
        hour: 21,
        day: 5,
        month: 9,
        reserved: 0xaa,
        year: 2009,
        weekday: 6,
        reserved2: 0xbb,
    };

    /// Every `find` call the fake provider chain has served.
    static mut FIND_CALLS: Vec<(*mut ResourceProvider, ResourceKind, u32)> = Vec::new();
    /// Which node answers: 0 = first node declines, 1 = second answers.
    static mut ANSWER_NODE: usize = 0;

    unsafe extern "C" fn mock_find(
        provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
        found: *mut *mut u8,
    ) -> u32 {
        (*ptr::addr_of_mut!(FIND_CALLS)).push((provider, kind, id));
        let node = if (*provider).next.is_null() { 1 } else { 0 };
        if node == *ptr::addr_of!(ANSWER_NODE) {
            *found = ptr::addr_of!(DEMO_RECORD) as *mut u8;
            1
        } else {
            0
        }
    }

    unsafe extern "C" fn unreachable_read(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
    ) -> u32 {
        std::panic!("demo_mode_datetime never reads through slot +0x58");
    }

    unsafe extern "C" fn unreachable_write(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
        _value: u32,
        _flags: u32,
    ) -> u32 {
        std::panic!("demo_mode_datetime never writes through slot +0x68");
    }

    /// One vtable serving both decodes of the demo-mode object:
    /// `cast_to_class` at +0x14 (FrameworkObjectVtable slot 5) and the
    /// resource-provider slots +0x58/+0x64/+0x68.
    #[repr(C)]
    struct DemoModeVtable {
        framework_below: [usize; 5],
        cast_to_class:
            unsafe extern "C" fn(this: *mut FrameworkObject, class_id: u32) -> *mut u8,
        provider_below: [usize; 16],
        read: ResourceReadFn,
        provider_between: [usize; 2],
        find: ResourceFindFn,
        write: ResourceWriteFn,
    }

    unsafe extern "C" fn mock_cast_to_class(
        this: *mut FrameworkObject,
        class_id: u32,
    ) -> *mut u8 {
        if class_id == crate::app::registry::CLASS_ID_DEMO_MODE {
            this.cast()
        } else {
            ptr::null_mut()
        }
    }

    static DEMO_VTABLE: DemoModeVtable = DemoModeVtable {
        framework_below: [0; 5],
        cast_to_class: mock_cast_to_class,
        provider_below: [0; 16],
        read: unreachable_read,
        provider_between: [0; 2],
        find: mock_find,
        write: unreachable_write,
    };

    /// The demo-mode object heads a two-node provider chain so the
    /// `next` walk is exercised too.
    static mut DEMO_NODE: ResourceProvider = ResourceProvider {
        vtable: ptr::null(),
        state_below_next: [ptr::null_mut(); 4],
        next: ptr::null_mut(),
    };
    static mut SECOND_NODE: ResourceProvider = ResourceProvider {
        vtable: ptr::null(),
        state_below_next: [ptr::null_mut(); 4],
        next: ptr::null_mut(),
    };

    // ---- the class registry `demo_mode_instance` resolves through ----

    unsafe extern "C" fn mock_index_of(_this: *mut Registry, key: *const u32) -> i32 {
        if *key == crate::app::registry::CLASS_ID_DEMO_MODE { 0 } else { -1 }
    }

    unsafe extern "C" fn mock_entry_at(
        _this: *mut Registry,
        _index: i32,
        out: *mut RegistryEntry,
    ) -> *mut RegistryEntry {
        out.write(RegistryEntry {
            class_id: crate::app::registry::CLASS_ID_DEMO_MODE,
            instance: ptr::addr_of_mut!(DEMO_NODE).cast(),
        });
        out
    }

    unsafe extern "C" fn unreachable_insert(
        _this: *mut Registry,
        _entry: *const RegistryEntry,
    ) -> usize {
        std::panic!("demo_mode_datetime inserts nothing into the registry");
    }

    unsafe extern "C" fn unreachable_assign_at(
        _this: *mut Registry,
        _index: i32,
        _entry: *const RegistryEntry,
    ) -> usize {
        std::panic!("demo_mode_datetime writes nothing to the registry");
    }

    unsafe extern "C" fn unreachable_notify(_this: *mut Registry) -> *mut u8 {
        std::panic!("demo_mode_datetime fires no registry notification");
    }

    static REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: unreachable_insert,
        unresolved_20: 0,
        assign_at: unreachable_assign_at,
        unresolved_28: [0; 5],
        entry_at: mock_entry_at,
        unresolved_40: [0; 3],
        index_of: mock_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: unreachable_notify,
        notify_deferred: unreachable_notify,
        notify_changed: unreachable_notify,
    };

    struct Fixture {
        _lock: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new(answer_node: usize) -> Fixture {
            let lock = CLASS_REGISTRY_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            unsafe {
                (*ptr::addr_of_mut!(FIND_CALLS)).clear();
                *ptr::addr_of_mut!(ANSWER_NODE) = answer_node;
                let vtable = ptr::addr_of!(DEMO_VTABLE);
                DEMO_NODE.vtable = vtable.cast();
                DEMO_NODE.next = ptr::addr_of_mut!(SECOND_NODE);
                SECOND_NODE.vtable = vtable.cast();
                SECOND_NODE.next = ptr::null_mut();
                CLASS_REGISTRY.vtable = &REGISTRY_VTABLE;
            }
            Fixture { _lock: lock }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                CLASS_REGISTRY.vtable = ptr::null();
                DEMO_NODE.vtable = ptr::null();
                DEMO_NODE.next = ptr::null_mut();
                SECOND_NODE.vtable = ptr::null();
            }
        }
    }

    /// The copy must move all ten bytes — a 10-byte copy of a distinct
    /// pattern proves neither a 4/8-byte truncation nor a shift.
    #[test]
    fn copies_the_whole_record_and_returns_out() {
        let _fixture = Fixture::new(0);
        let mut out = DateTime {
            second: 0xff,
            minute: 0xff,
            hour: 0xff,
            day: 0xff,
            month: 0xff,
            reserved: 0xff,
            year: 0xffff,
            weekday: 0xff,
            reserved2: 0xff,
        };
        let returned = unsafe { demo_mode_datetime(&mut out) };
        assert_eq!(returned, &mut out as *mut DateTime);
        assert_eq!(out, DEMO_RECORD);
    }

    /// `size_of::<DateTime>()` must be the original's literal `mov
    /// r2, #10`, or the port's copy length silently diverges.
    #[test]
    fn record_is_exactly_ten_bytes() {
        assert_eq!(core::mem::size_of::<DateTime>(), 10);
    }

    /// The find must go to the demo-mode object itself with exactly
    /// the (kind "DtTm", id 0x80aa) pair — the two literal-pool words.
    #[test]
    fn asks_the_demo_mode_chain_for_dttm_80aa() {
        let _fixture = Fixture::new(0);
        let mut out = DEMO_RECORD;
        unsafe { demo_mode_datetime(&mut out) };
        let calls = unsafe { &*ptr::addr_of!(FIND_CALLS) };
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, unsafe { ptr::addr_of_mut!(DEMO_NODE) });
        assert_eq!(calls[0].1, ResourceKind(0x4474_546d));
        assert_eq!(calls[0].2, 0x80aa);
    }

    /// A declining first node must not stop the fetch: the walk
    /// continues along `next`, exactly as `resource_chain_find` does.
    #[test]
    fn walks_past_a_declining_provider() {
        let _fixture = Fixture::new(1);
        let mut out = DEMO_RECORD;
        out.second = 0xff;
        let returned = unsafe { demo_mode_datetime(&mut out) };
        assert_eq!(returned, &mut out as *mut DateTime);
        assert_eq!(out, DEMO_RECORD);
        let calls = unsafe { &*ptr::addr_of!(FIND_CALLS) };
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, unsafe { ptr::addr_of_mut!(SECOND_NODE) });
    }
}

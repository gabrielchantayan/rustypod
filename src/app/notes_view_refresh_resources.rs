//! Notes resource refresh — `FUN_0828a8d0` at `0x0828a8d0`.
//! True extent: 168 bytes through `0x0828a978` (140 code, 28 literals).
//! Raw A32 decoding finds two plain inbound BLs (0x081176b8, 0x0828ae38),
//! zero predicated inbound BLs and zero outbound direct BLs. Four plain
//! indirect BLX calls precede a BX tail dispatch through vtable slot +0x58.
//!
//! Dispatch VMax/0x4182, Str /0x4184, VMax/0x4188, Str /0x418a and
//! Str /0x41a0, reloading the receiver's vtable for each notification.
//! Preserve the final dispatch result in r0; Ghidra's void return loses it.
//! Deliberate deviations: host vtable cells widen to pointer size via repr(C).
//! Virtual callees remain unidentified; no fixed-address callee seam is added.

use core::ptr;

pub type ResourceDispatch = unsafe extern "C" fn(*mut NotesResourceReceiver, u32, u32) -> u32;

/// Prefix of the receiver; all remaining state belongs to the virtual callee.
#[repr(C)]
pub struct NotesResourceReceiver {
    pub vtable: *const NotesResourceVtable,
}

/// The dispatch entry is word 22 (+0x58) on ARM.
#[repr(C)]
pub struct NotesResourceVtable {
    pub preceding_slots: [usize; 22],
    pub dispatch: ResourceDispatch,
}

#[inline(always)]
unsafe fn dispatch(receiver: *mut NotesResourceReceiver, kind: u32, resource: u32) -> u32 {
    let vtable = ptr::read_volatile(ptr::addr_of!((*receiver).vtable));
    let method = ptr::read_volatile(ptr::addr_of!((*vtable).dispatch));
    method(receiver, kind, resource)
}

/// Refreshes the Notes view's selected-resource notifications.
///
/// # Safety
/// `receiver` must have a readable vtable with a valid dispatch entry before
/// every call. Its allocation must satisfy all five virtual call contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn notes_view_refresh_resources(receiver: *mut NotesResourceReceiver) -> u32 {
    dispatch(receiver, 0x564d_6178, 0x4182);
    dispatch(receiver, 0x5374_7220, 0x4184);
    dispatch(receiver, 0x564d_6178, 0x4188);
    dispatch(receiver, 0x5374_7220, 0x418a);
    dispatch(receiver, 0x5374_7220, 0x41a0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        receiver: NotesResourceReceiver,
        calls: [(u32, u32, u32); 5],
        count: usize,
        switch_table: bool,
    }

    unsafe fn record(receiver: *mut NotesResourceReceiver, kind: u32, resource: u32, table: u32) -> u32 {
        let fixture = &mut *receiver.cast::<Fixture>();
        fixture.calls[fixture.count] = (table, kind, resource);
        fixture.count += 1;
        if fixture.switch_table {
            fixture.receiver.vtable = if table == 1 { &SECOND } else { &FIRST };
        }
        if fixture.count == 5 { 0xfedc_ba98 } else { 0x1234_5678 }
    }

    unsafe extern "C" fn first(receiver: *mut NotesResourceReceiver, kind: u32, resource: u32) -> u32 {
        record(receiver, kind, resource, 1)
    }
    unsafe extern "C" fn second(receiver: *mut NotesResourceReceiver, kind: u32, resource: u32) -> u32 {
        record(receiver, kind, resource, 2)
    }
    static FIRST: NotesResourceVtable = NotesResourceVtable { preceding_slots: [0; 22], dispatch: first };
    static SECOND: NotesResourceVtable = NotesResourceVtable { preceding_slots: [0; 22], dispatch: second };

    fn check(switch_table: bool, tables: [u32; 5]) {
        let mut fixture = Fixture {
            receiver: NotesResourceReceiver { vtable: &FIRST },
            calls: [(0, 0, 0); 5], count: 0, switch_table,
        };
        let result = unsafe { notes_view_refresh_resources(&mut fixture.receiver) };
        assert_eq!(result, 0xfedc_ba98);
        assert_eq!(fixture.count, 5);
        let reference = [
            (tables[0], 0x564d_6178, 0x4182),
            (tables[1], 0x5374_7220, 0x4184),
            (tables[2], 0x564d_6178, 0x4188),
            (tables[3], 0x5374_7220, 0x418a),
            (tables[4], 0x5374_7220, 0x41a0),
        ];
        assert_eq!(fixture.calls, reference);
    }

    #[test]
    fn preserves_order_and_final_full_width_result() {
        check(false, [1; 5]);
    }

    #[test]
    fn reloads_vtable_after_every_dispatch_including_tail() {
        check(true, [1, 2, 1, 2, 1]);
    }
}

//! Voice-memo calendar/resource refresh — `FUN_081a47d4` @ **0x081a47d4**.
//!
//! True extent: **228 bytes**, 0x081a47d4..0x081a48b8: 192 code bytes
//! and nine literal words, followed by a distinct push-based function.
//! Whole-image aligned A32 decoding: two inbound plain BLs (0x081a3980,
//! 0x083a1c3c), zero predicated BLs. Outgoing: one plain BL to
//! voice_memo_duration_query @ 0x081a4b88, zero predicated BLs, six virtual
//! BLXs and a final indirect BX.
//!
//! Refresh the embedded duration calendar using selector 'DtTm', ignoring
//! its pointer result, then dispatch category 0x2a2a2a2a to resources 0x3d04
//! and 0x3d0a..0x3d0f through vtable +0x58. Reload the vtable after each
//! callback; return the final callback's r0 word. Callee identity is opaque.
//!
//! Deviations: reuse the repr(C) resource object/vtable layout, whose pointers
//! widen on hosts while preserving slot indices. Rust returns the final
//! virtual result without requiring an indirect tail branch; Ghidra's void
//! signature is corrected to retain the raw r0 result. Duration conversion
//! uses the existing port and its existing calendar/recorder seams.

use super::selection_dispatch_resource_updates::SelectionResourceObject;
use super::voice_memo_duration::{voice_memo_duration_query, DURATION_DATETIME};

/// # Safety
/// `controller` must be aligned and writable through +0xd4, with a valid
/// resource dispatch vtable. Active controllers require the duration query's
/// recorder invariants. Callbacks may replace the vtable but must leave the
/// controller and subsequent dispatch slot valid. No NULL checks are added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn voice_memo_resource_refresh(controller: *mut SelectionResourceObject) -> u32 {
    voice_memo_duration_query(controller.cast(), DURATION_DATETIME);
    let mut result = 0;
    for resource in [0x3d04, 0x3d0a, 0x3d0b, 0x3d0c, 0x3d0d, 0x3d0e, 0x3d0f] {
        let dispatch = (*(*controller).vtable).dispatch;
        result = dispatch(controller, 0x2a2a_2a2a, resource);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::selection_dispatch_resource_updates::SelectionResourceVtable;
    use crate::time::datetime::DateTime;
    use crate::time::unix_to_datetime::{DAY_NUMBER_TO_DATETIME, DAY_NUMBER_TO_DATETIME_TEST_LOCK, DayNumberToDateTimeFn};

    #[repr(C)]
    struct Fixture {
        // Target byte offsets used by the real duration callee remain fixed.
        storage: [usize; 0xd8 / core::mem::size_of::<usize>()],
        replacement: *const SelectionResourceVtable,
        state: u32,
        calls: u32,
        observed_seconds: u8,
    }

    unsafe extern "C" fn calendar(_: u32, out: *mut DateTime) {
        core::ptr::write_bytes(out.cast::<u8>(), 0xa5, 10);
    }
    unsafe extern "C" fn initial(object: *mut SelectionResourceObject, category: u32, resource: u32) -> u32 {
        let fixture = &mut *object.cast::<Fixture>();
        fixture.observed_seconds = object.cast::<u8>().add(0x80).read();
        fixture.state = fixture.state.rotate_left(7) ^ category ^ resource;
        fixture.calls += 1;
        (*object).vtable = fixture.replacement;
        0xdead_beef
    }
    unsafe extern "C" fn changed(object: *mut SelectionResourceObject, category: u32, resource: u32) -> u32 {
        let fixture = &mut *object.cast::<Fixture>();
        fixture.state = fixture.state.wrapping_mul(33) ^ category ^ resource;
        fixture.calls += 1;
        fixture.state
    }
    struct Restore(DayNumberToDateTimeFn);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { core::ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME).write(self.0) }; }
    }

    #[test]
    fn refreshes_calendar_before_dispatch_reloads_vtable_and_preserves_final_word() {
        let _duration_lock = super::super::voice_memo_duration::tests::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _calendar_lock = DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = Restore(core::ptr::addr_of!(DAY_NUMBER_TO_DATETIME).read());
            core::ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME).write(calendar);
            let first = SelectionResourceVtable { preceding_slots: [0; 22], dispatch: initial };
            let second = SelectionResourceVtable { preceding_slots: [0; 22], dispatch: changed };
            for seed in [0u32, 1, 0x8000_0000, u32::MAX] {
                let mut fixture = Fixture { storage: [0; 0xd8 / core::mem::size_of::<usize>()], replacement: &second,
                    state: seed, calls: 0, observed_seconds: 0xff };
                let object = fixture.storage.as_mut_ptr().cast::<SelectionResourceObject>();
                (*object).vtable = &first;
                // An inactive controller must still recompute the calendar.
                object.cast::<u8>().add(0x80).write(0xff);
                let result = voice_memo_resource_refresh(object);
                let mut expected = seed.rotate_left(7) ^ 0x2a2a_2a2a ^ 0x3d04;
                for resource in 0x3d0a..=0x3d0f { expected = expected.wrapping_mul(33) ^ 0x2a2a_2a2a ^ resource; }
                assert_eq!(result, expected);
                assert_eq!(fixture.state, expected);
                assert_eq!(fixture.calls, 7);
                assert_eq!(fixture.observed_seconds, 0);
                assert_eq!(core::slice::from_raw_parts(object.cast::<u8>().add(0x80), 3), &[0, 0, 0]);
                assert_eq!(object.cast::<u8>().add(0x83).read(), 0xa5);
                assert_eq!((*object).vtable, &second as *const _);
            }
        }
    }
}

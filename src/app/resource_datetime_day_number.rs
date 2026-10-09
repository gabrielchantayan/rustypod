//! Calendar resource day-number lookup: `FUN_080d890c` @ 0x080d890c.
//!
//! True extent: 60 bytes, [0x080d890c, 0x080d8948), comprising 52 code
//! bytes and literals 0x80aa / 0x4474546d. The next function starts with
//! `cmp r0, #44` at 0x080d8948. Whole-image aligned ARM BL decoding finds
//! two plain inbound calls (0x08140bc0, 0x0814141c), zero predicated calls;
//! the body has two plain outbound BLs and zero predicated BLs.
//!
//! Return zero for a NULL provider or missing ("DtTm", 0x80aa) resource.
//! Otherwise convert the returned packed DateTime to its Rata Die day
//! number, updating its weekday byte through datetime_day_number.
//! Both raw callers pass the result of 0x081883fc and save the day at +0xe8.
//! No new callee seam or behavioral deviation: reuse the already ported
//! resource_chain_find and datetime_day_number, including their contracts.

use super::resource_chain::{resource_chain_find, ResourceKind, ResourceProvider};
use crate::time::datetime::DateTime;
use crate::time::day_number::datetime_day_number;

/// Resolve the calendar resource and return its day number, or zero.
///
/// # Safety
/// Every reachable provider must satisfy resource_chain_find's contract.
/// A non-NULL answer must be an aligned, readable and writable DateTime.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn resource_datetime_day_number(head: *mut ResourceProvider) -> i32 {
    if head.is_null() {
        return 0;
    }
    let record = resource_chain_find(head, ResourceKind(0x4474_546d), 0x80aa);
    if record.is_null() {
        return 0;
    }
    datetime_day_number(record.cast::<DateTime>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::resource_chain::ResourceProviderVTable;
    use core::ptr;

    unsafe extern "C" fn find(
        provider: *mut ResourceProvider, kind: ResourceKind, id: u32,
        found: *mut *mut u8,
    ) -> u32 {
        assert_eq!(kind, ResourceKind(0x4474_546d));
        assert_eq!(id, 0x80aa);
        *found = (*provider).state_below_next[0];
        (!(*found).is_null()) as u32
    }

    unsafe extern "C" fn read(_: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 {
        panic!("unexpected resource read")
    }
    unsafe extern "C" fn replace(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 {
        panic!("unexpected provider replacement")
    }
    unsafe extern "C" fn write(
        _: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32,
    ) -> u32 {
        panic!("unexpected resource write")
    }

    static VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22], read, slot_5c: None,
        replacement_allowed: replace, find, write,
    };

    fn provider(record: *mut DateTime, next: *mut ResourceProvider) -> ResourceProvider {
        ResourceProvider {
            vtable: &VTABLE,
            state_below_next: [record.cast(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut()],
            next,
        }
    }

    #[test]
    fn empty_and_missing_resources_return_zero() {
        let mut missing = provider(ptr::null_mut(), ptr::null_mut());
        unsafe {
            assert_eq!(resource_datetime_day_number(ptr::null_mut()), 0);
            assert_eq!(resource_datetime_day_number(&mut missing), 0);
        }
    }

    #[test]
    fn chained_calendar_dates_update_only_weekday() {
        let _guard = crate::time::day_number::DAY_NUMBER_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        // Known Rata Die anchors, including century leap/non-leap boundaries.
        for (year, month, day, expected) in [
            (1, 1, 1, 1), (1970, 1, 1, 719163),
            (2000, 2, 29, 730179), (2000, 3, 1, 730180),
            (1900, 2, 28, 693654), (1900, 3, 1, 693655),
        ] {
            let mut record = DateTime {
                second: 59, minute: 58, hour: 23, day, month,
                reserved: 0xa5, year, weekday: 0xff, reserved2: 0x5a,
            };
            let before = record;
            let mut answer = provider(&mut record, ptr::null_mut());
            let mut missing = provider(ptr::null_mut(), &mut answer);
            unsafe { assert_eq!(resource_datetime_day_number(&mut missing), expected); }
            assert_eq!(record.weekday, (expected % 7) as u8);
            assert_eq!(record, DateTime { weekday: (expected % 7) as u8, ..before });
        }
    }
}

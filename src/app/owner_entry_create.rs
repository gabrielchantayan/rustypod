//! Allocate, initialize and append an owner entry: retailOS 0x0805e5f4.
//! True extent [0x0805e5f4,0x0805e66c), 120 bytes, ending in POP before
//! the next dirty-marker function. Raw A32 scan: two inbound plain BLs
//! (0x080954c0,0x080d71e4), no predicated inbound BLs; four outbound plain
//! BLs, no predicated outbound BLs. Reject unsigned count >= 0x7fffffff;
//! acquire from owner +0x44; initialize owner, kind, sequence, byte +0x16,
//! owner-relative pointer +0x918 and timestamp +0x58, then append. Zero
//! timestamp selects current Macintosh-epoch seconds. Argument r2 is unused.
//! Deviations: reuse FIXED_POOL_OPS for the unported 0x0805de1c allocator;
//! native repr(C) pointers widen on hosts, preserving typed field access.
//! Other calls use their existing Rust ports, not new dispatch seams.

use core::ptr;
use super::owner_entry_append::{owner_entry_append, EntryOwner, OwnerEntry};
use crate::ui::pool_entry_create::FIXED_POOL_OPS;

/// Owner prefix through the entry's owner-relative anchor at target +0x918.
#[repr(C)]
pub struct EntryCreateOwner {
    pub list: EntryOwner,
    pub reserved_to_pool: [u32; 5],
    pub pool: *mut u8,
    pub reserved_to_anchor: [u32; 564],
    pub anchor: u32,
}

/// Entry prefix through its timestamp; untouched fields retain pool contents.
#[repr(C)]
pub struct CreatedOwnerEntry {
    pub links: OwnerEntry,
    pub kind: u32,
    pub anchor: *mut u32,
    pub flags: [u8; 4],
    pub sequence: u32,
    pub reserved_to_timestamp: [u32; 15],
    pub timestamp: u32,
}

/// # Safety
/// Owner must be live and readable. Successful pool acquisition must return
/// an aligned writable entry of the retail pool's full size. Existing append
/// and current-time contracts apply; on target the owner helper uses +0x900.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_entry_create(
    owner: *mut EntryCreateOwner, kind: u32, _unused: u32, timestamp: u32,
) -> *mut CreatedOwnerEntry {
    if (*owner).list.count >= 0x7fff_ffff {
        return ptr::null_mut();
    }
    let ops = ptr::read_volatile(ptr::addr_of!(FIXED_POOL_OPS));
    let entry = (ops.acquire)((*owner).pool).cast::<CreatedOwnerEntry>();
    if entry.is_null() {
        return entry;
    }
    (*entry).links.owner = ptr::addr_of_mut!((*owner).list);
    (*entry).kind = kind;
    (*entry).sequence = crate::ui::object_state::sequence_id_next();
    (*entry).flags[2] = 0;
    (*entry).anchor = ptr::addr_of_mut!((*owner).anchor);
    if timestamp == 0 {
        crate::time::current_mac_epoch_seconds_raw::current_mac_epoch_seconds_raw(
            ptr::addr_of_mut!((*entry).timestamp));
    } else {
        (*entry).timestamp = timestamp;
    }
    owner_entry_append(ptr::addr_of_mut!((*entry).links));
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::owner_entry_append::OWNER_ENTRY_TAIL_HELPER;
    use crate::ui::pool_entry_create::FixedPoolOps;
    use crate::time::datetime::DateTime;

    static mut ALLOCATION: *mut CreatedOwnerEntry = ptr::null_mut();
    static mut ACQUIRES: u32 = 0;
    static mut APPENDS: u32 = 0;
    static mut QUERIES: u32 = 0;

    unsafe extern "C" fn acquire(pool: *mut u8) -> *mut u8 {
        assert_eq!(pool as usize, 0x1234);
        ACQUIRES += 1;
        ALLOCATION.cast()
    }
    unsafe extern "C" fn appended(owner: *mut EntryOwner) {
        let entry = (*owner).tail.cast::<CreatedOwnerEntry>();
        assert_eq!((*entry).links.owner, owner);
        assert_eq!((*entry).flags[2], 0);
        assert_eq!((*entry).anchor, ptr::addr_of_mut!((*owner.cast::<EntryCreateOwner>()).anchor));
        assert_ne!((*entry).timestamp, 0);
        APPENDS += 1;
    }
    unsafe extern "C" fn query(out: *mut u8) -> bool {
        let calendar = [0, 0, 3, 2, 1, 1, 1, 0, 0x70, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ptr::copy_nonoverlapping(calendar.as_ptr(), out, 20);
        QUERIES += 1;
        true
    }
    unsafe extern "C" fn normalize(_: u32, out: *mut DateTime) {
        *out = DateTime { second: 3, minute: 2, hour: 1, day: 1, month: 1,
            reserved: 0, year: 1904, weekday: 0, reserved2: 0 };
    }

    struct Restore {
        pool: FixedPoolOps,
        tail: unsafe extern "C" fn(*mut EntryOwner),
        sequence: u32,
        query: usize,
        normalize: crate::time::unix_to_datetime::DayNumberToDateTimeFn,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                FIXED_POOL_OPS = self.pool;
                OWNER_ENTRY_TAIL_HELPER = self.tail;
                crate::ui::object_state::SEQUENCE_ID = self.sequence;
                crate::fp::fp_misc::CURRENT_DATETIME_QUERY = self.query;
                crate::time::unix_to_datetime::DAY_NUMBER_TO_DATETIME = self.normalize;
            }
        }
    }

    #[test]
    fn count_limit_failure_and_timestamp_paths_preserve_entry_state() {
        let _pool = crate::testing::UI_POOL_ENTRY_CREATE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _sequence = crate::testing::SEQUENCE_ID_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _tail = crate::testing::OWNER_ENTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _query = crate::fp::fp_misc::CURRENT_DATETIME_QUERY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _normalize = crate::time::unix_to_datetime::DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = Restore { pool: FIXED_POOL_OPS, tail: OWNER_ENTRY_TAIL_HELPER,
                sequence: crate::ui::object_state::SEQUENCE_ID,
                query: crate::fp::fp_misc::CURRENT_DATETIME_QUERY,
                normalize: crate::time::unix_to_datetime::DAY_NUMBER_TO_DATETIME };
            FIXED_POOL_OPS = FixedPoolOps { acquire };
            OWNER_ENTRY_TAIL_HELPER = appended;
            crate::fp::fp_misc::CURRENT_DATETIME_QUERY = query as *const () as usize;
            crate::time::unix_to_datetime::DAY_NUMBER_TO_DATETIME = normalize;
            crate::ui::object_state::SEQUENCE_ID = u32::MAX;
            ACQUIRES = 0; APPENDS = 0; QUERIES = 0; ALLOCATION = ptr::null_mut();
            let mut owner: EntryCreateOwner = core::mem::zeroed();
            owner.pool = 0x1234usize as *mut u8;
            for count in [0x7fff_ffff, 0x8000_0000, u32::MAX] {
                owner.list.count = count;
                assert!(owner_entry_create(&mut owner, 7, 99, 0).is_null());
                assert_eq!(owner.list.count, count);
            }
            assert_eq!(ACQUIRES, 0);
            owner.list.count = 0;
            assert!(owner_entry_create(&mut owner, 7, 99, 0).is_null());
            assert_eq!(ACQUIRES, 1);
            assert_eq!(owner.list.count, 0);
            assert!(owner.list.head.is_null());
            assert_eq!(crate::ui::object_state::SEQUENCE_ID, u32::MAX);
            assert_eq!(QUERIES, 0);
            assert_eq!(APPENDS, 0);

            let mut entries: [CreatedOwnerEntry; 2] = core::mem::zeroed();
            for (i, timestamp) in [u32::MAX, 0].into_iter().enumerate() {
                entries[i].flags = [0xa5; 4];
                entries[i].reserved_to_timestamp = [0x12345678; 15];
                ALLOCATION = &mut entries[i];
                let result = owner_entry_create(&mut owner, 0xabcdef12, 99, timestamp);
                assert_eq!(result, &mut entries[i] as *mut _);
                assert_eq!((*result).kind, 0xabcdef12);
                assert_eq!((*result).sequence, if i == 0 { u32::MAX } else { 0 });
                assert_eq!((*result).flags, [0xa5, 0xa5, 0, 0xa5]);
                assert_eq!((*result).reserved_to_timestamp, [0x12345678; 15]);
                assert_eq!((*result).timestamp, if i == 0 { u32::MAX } else { 3723 });
                assert_eq!(owner.list.count, i as u32 + 1);
                assert_eq!(QUERIES, i as u32);
            }
            assert_eq!(APPENDS, 2);
            let first = ptr::addr_of_mut!(entries[0].links);
            let second = ptr::addr_of_mut!(entries[1].links);
            assert_eq!(entries[0].links.next, second);
            assert_eq!(entries[1].links.previous, first);
            assert!(entries[1].links.next.is_null());
            assert_eq!(owner.list.head, &mut entries[0].links as *mut _);
            assert_eq!(owner.list.tail, &mut entries[1].links as *mut _);
            assert_eq!(crate::ui::object_state::SEQUENCE_ID, 1);

            owner.list.count = 0x7fff_fffe;
            owner.list.head = ptr::null_mut(); owner.list.tail = ptr::null_mut();
            ALLOCATION = &mut entries[0];
            assert!(!owner_entry_create(&mut owner, 1, 0, 1).is_null());
            assert_eq!(owner.list.count, 0x7fff_ffff);
        }
    }
}

//! `vtable_slot_10_flagged_payload_address` — `FUN_081fcab0` at
//! 0x081fcab0, 52 bytes (through POP at 0x081fcae0; next PUSH at 0x081fcae4).
//! Two incoming plain BL sites: 0x081f0714 and 0x081fcbd8; no predicated BLs.
//! Body: one plain BL to flagged_pair_payload_if_set, no predicated BLs,
//! and one unconditional indirect BLX through vtable slot +0x10.
//!
//! Algorithm: forward the receiver and selector to the unresolved virtual
//! query. Return zero for a NULL record or a clear low flag bit; otherwise
//! read the record's second word and return its wrapping sum with 0x14.
//! The payload word is not NULL-checked. The virtual method's identity is
//! deliberately not inferred from its slot. Deviations: native-width typed
//! vtable pointers on hosts; the record and returned address remain u32.

use super::flagged_pair_copy::FlaggedPair;
use super::flagged_pair_payload::flagged_pair_payload_if_set;

pub type FlaggedRecordQuery = unsafe extern "C" fn(*mut FlaggedPayloadReceiver, u32) -> *mut FlaggedPair;

#[repr(C)]
pub struct FlaggedPayloadVtable {
    pub unresolved_slots: [Option<unsafe extern "C" fn()>; 4],
    pub query: FlaggedRecordQuery,
}

#[repr(C)]
pub struct FlaggedPayloadReceiver {
    pub vtable: *const FlaggedPayloadVtable,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(FlaggedPayloadVtable, query)];

/// # Safety
/// The receiver must have a readable vtable and callable +0x10 slot accepting
/// the selector. A non-NULL query result must be a readable flagged pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_slot_10_flagged_payload_address(
    receiver: *mut FlaggedPayloadReceiver,
    selector: u32,
) -> u32 {
    let query = unsafe { (*(*receiver).vtable).query };
    let record = unsafe { query(receiver, selector) };
    if record.is_null() {
        return 0;
    }
    let payload = unsafe { flagged_pair_payload_if_set(record) };
    if payload.is_null() {
        return 0;
    }
    unsafe { payload.cast::<u32>().read() }.wrapping_add(0x14)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        receiver: FlaggedPayloadReceiver,
        records: [FlaggedPair; 2],
    }

    unsafe extern "C" fn query(receiver: *mut FlaggedPayloadReceiver, selector: u32) -> *mut FlaggedPair {
        if selector > 1 {
            core::ptr::null_mut()
        } else {
            unsafe { core::ptr::addr_of_mut!((*receiver.cast::<Fixture>()).records).cast::<FlaggedPair>().add(selector as usize) }
        }
    }

    fn record(second: u32, flag: u8) -> FlaggedPair {
        FlaggedPair { first: 0xdead_beef, second, flag, reserved: [0xa5; 3] }
    }

    #[test]
    fn null_query_and_all_clear_low_bits_return_zero() {
        let vtable = FlaggedPayloadVtable { unresolved_slots: [None; 4], query };
        let mut fixture = Fixture {
            receiver: FlaggedPayloadReceiver { vtable: &vtable },
            records: [record(0xffff_ffff, 0), record(0x0800_0000, 1)],
        };
        assert_eq!(unsafe { vtable_slot_10_flagged_payload_address(&mut fixture.receiver, u32::MAX) }, 0);
        for flag in (0..=254).step_by(2) {
            fixture.records[0].flag = flag;
            assert_eq!(unsafe { vtable_slot_10_flagged_payload_address(&mut fixture.receiver, 0) }, 0);
        }
        assert_eq!(unsafe { vtable_slot_10_flagged_payload_address(&mut fixture.receiver, 1) }, 0x0800_0014);
    }

    #[test]
    fn flagged_payload_addition_wraps_and_does_not_check_null_word() {
        let vtable = FlaggedPayloadVtable { unresolved_slots: [None; 4], query };
        let mut fixture = Fixture {
            receiver: FlaggedPayloadReceiver { vtable: &vtable },
            records: [record(0, 1), record(0, 0)],
        };
        for flag in (1..=255).step_by(2) {
            fixture.records[0].flag = flag;
            for (word, expected) in [(0, 0x14), (0x0800_0000, 0x0800_0014), (0xffff_ffeb, u32::MAX), (0xffff_ffec, 0), (u32::MAX, 0x13)] {
                fixture.records[0].second = word;
                assert_eq!(unsafe { vtable_slot_10_flagged_payload_address(&mut fixture.receiver, 0) }, expected);
                assert_eq!(fixture.records[0].first, 0xdead_beef);
                assert_eq!(fixture.records[0].second, word);
                assert_eq!(fixture.records[0].flag, flag);
                assert_eq!(fixture.records[0].reserved, [0xa5; 3]);
            }
        }
    }
}

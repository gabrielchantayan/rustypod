//! Guarded 64-bit backing-record value accessor.
//!
//! Original: `FUN_082a2fb0` @ `0x082a2fb0`, 52 bytes, true extent
//! `0x082a2fb0..0x082a2fe4`; the next function begins with push {r4,lr}.
//! Raw-image A32 decoding finds two inbound plain BLs (0x081fd1ec,
//! 0x08208bd4), zero predicated BLs. Body: zero direct BLs, one BLX r1.
//! Calls the object's virtual query at +8. If it returns zero, returns zero
//! without touching the backing record; otherwise reads the low/high words
//! at backing +0x110/+0x114, after the query. Ghidra loses the high return
//! register; callers and raw words establish a u64 result.
//! Deliberate deviation: host object/vtable pointer fields widen through
//! repr(C), preserving field roles rather than ARM byte offsets. Backing
//! words remain four bytes apart. No semantic deviations or new callee seam;
//! the virtual query's concrete identity and the value's units are unknown.

pub type RecordValueQuery = unsafe extern "C" fn(*mut GuardedRecord) -> u32;

#[repr(C)]
pub struct GuardedRecordVtable {
    pub unresolved_00: usize,
    pub unresolved_04: usize,
    pub query: RecordValueQuery,
}

#[repr(C)]
pub struct GuardedRecord {
    pub vtable: *const GuardedRecordVtable,
    pub unresolved_04: u32,
    pub backing: *const u32,
}

/// Returns the record's 64-bit value only when its virtual query succeeds.
///
/// # Safety
/// `record` and its vtable query must be valid. After a nonzero query result,
/// the (possibly replaced) backing pointer must permit aligned reads of words
/// 68 and 69. The query follows the retailOS ABI and may mutate the record.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn guarded_record_value(record: *mut GuardedRecord) -> u64 {
    let vtable = unsafe { (*record).vtable };
    if unsafe { ((*vtable).query)(record) } == 0 {
        return 0;
    }
    let backing = unsafe { (*record).backing };
    let low = unsafe { backing.add(0x110 / 4).read() };
    let high = unsafe { backing.add(0x114 / 4).read() };
    (low as u64) | ((high as u64) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn query(record: *mut GuardedRecord) -> u32 {
        unsafe { (*record).unresolved_04 }
    }
    static VTABLE: GuardedRecordVtable = GuardedRecordVtable {
        unresolved_00: 0, unresolved_04: 0, query,
    };

    #[test]
    fn failed_query_does_not_read_null_backing() {
        let mut record = GuardedRecord {
            vtable: &VTABLE, unresolved_04: 0, backing: core::ptr::null(),
        };
        assert_eq!(unsafe { guarded_record_value(&mut record) }, 0);
    }

    #[test]
    fn nonzero_query_preserves_both_words() {
        for ready in [1, 2, 0x8000_0000, u32::MAX] {
            for value in [0, 1, 0x8000_0000_0000_0000, 0x0123_4567_89ab_cdef, u64::MAX] {
                let mut backing = [0xa5a5_a5a5; 71];
                backing[68] = value as u32;
                backing[69] = (value >> 32) as u32;
                let before = backing;
                let mut record = GuardedRecord {
                    vtable: &VTABLE, unresolved_04: ready, backing: backing.as_ptr(),
                };
                assert_eq!(unsafe { guarded_record_value(&mut record) }, value);
                assert_eq!(backing, before);
            }
        }
    }

    unsafe extern "C" fn replace_backing(record: *mut GuardedRecord) -> u32 {
        unsafe { (*record).backing = (*record).backing.add(70); }
        1
    }

    #[test]
    fn backing_is_loaded_after_virtual_query() {
        let vtable = GuardedRecordVtable {
            unresolved_00: 0, unresolved_04: 0, query: replace_backing,
        };
        let mut backing = [0; 140];
        backing[68] = 0xdead_beef;
        backing[138] = 0x7654_3210;
        backing[139] = 0xfedc_ba98;
        let mut record = GuardedRecord {
            vtable: &vtable, unresolved_04: 0, backing: backing.as_ptr(),
        };
        assert_eq!(unsafe { guarded_record_value(&mut record) }, 0xfedc_ba98_7654_3210);
        assert_eq!(record.backing, unsafe { backing.as_ptr().add(70) });
    }
}

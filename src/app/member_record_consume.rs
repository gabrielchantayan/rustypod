//! Consume member record — FUN_08127af4 @ 0x08127af4.
//! Raw extent [0x08127af4,0x08127b88): 148 bytes (136 code, 12 literals),
//! next independent push at 0x08127b88. Two inbound plain BLs, zero
//! predicated; outbound zero plain BLs, one BLNE to operator_delete,
//! and four unconditional virtual BLX calls.
//!
//! Read member +0xfc slot zero through vtable +0x40, save its record,
//! invoke member +0x2c with zero, then cache record word +8 at owner +0xf8.
//! Dispatch Str properties 0x36c3 and 0x36c4 through owner +0x58, reloading
//! the vtable each time, then tag-2-delete the saved record. Record must be
//! non-null even though deletion is guarded. Ghidra's noreturn is incorrect.
//! Deviations: native pointers/vtable slots widen on hosts; repr(C) retains
//! target offsets. Incidental scratch arguments are not modeled. Tests
//! substitute deletion only; target calls the existing Rust delete port.
//! ARM match: all four virtual calls and field offsets agree. LLVM builds
//! resource IDs with immediates and tail-calls delete, eliding the redundant
//! null check after the required record dereference; delete itself guards null.

use core::ptr::{addr_of, addr_of_mut};

#[repr(C)]
pub struct ConsumedRecord {
    pub opaque: [u32; 2],
    pub value: u32,
}

#[repr(C)]
pub struct RecordMember {
    pub vtable: *const RecordMemberVTable,
}

#[repr(C)]
pub struct RecordMemberVTable {
    pub prefix: [usize; 11],
    pub remove: unsafe extern "C" fn(*mut RecordMember, u32),
    pub middle: [usize; 4],
    pub get: unsafe extern "C" fn(*mut RecordMember, u32) -> *mut *mut ConsumedRecord,
}

#[repr(C)]
pub struct RecordConsumerVTable {
    pub prefix: [usize; 22],
    pub dispatch: unsafe extern "C" fn(*mut RecordConsumer, u32, u32),
}

#[repr(C)]
pub struct RecordConsumer {
    pub vtable: *const RecordConsumerVTable,
    pub opaque: [u32; 61],
    pub cached_value: u32,
    pub member: RecordMember,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(RecordConsumer, cached_value) == 0xf8);
    assert!(core::mem::offset_of!(RecordConsumer, member) == 0xfc);
    assert!(core::mem::offset_of!(RecordMemberVTable, remove) == 0x2c);
    assert!(core::mem::offset_of!(RecordMemberVTable, get) == 0x40);
    assert!(core::mem::offset_of!(RecordConsumerVTable, dispatch) == 0x58);
};

#[inline(always)]
unsafe fn consume_with(owner: *mut RecordConsumer, delete: impl FnOnce(*mut u8)) {
    let member = addr_of_mut!((*owner).member);
    let table = addr_of!((*member).vtable).read_volatile();
    let slot = ((*table).get)(member, 0);
    let record = slot.read();
    let table = addr_of!((*member).vtable).read_volatile();
    ((*table).remove)(member, 0);
    addr_of_mut!((*owner).cached_value).write((*record).value);
    for resource in [0x36c3, 0x36c4] {
        let table = addr_of!((*owner).vtable).read_volatile();
        ((*table).dispatch)(owner, 0x5374_7220, resource);
    }
    if !record.is_null() { delete(record.cast()); }
}

/// # Safety
/// Owner and virtual tables must be live and aligned; member slot zero must
/// return a readable non-null record. Removal and dispatch must keep that
/// record and owner alive. The record must support tag-2 deletion.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn member_record_consume(owner: *mut RecordConsumer) {
    consume_with(owner, |record| crate::heap::veneers::operator_delete(record));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        owner: RecordConsumer,
        slot: *mut ConsumedRecord,
        stage: u32,
    }

    unsafe fn fixture(member: *mut RecordMember) -> *mut Fixture {
        member.cast::<u8>().sub(core::mem::offset_of!(RecordConsumer, member)).cast()
    }

    unsafe extern "C" fn get(member: *mut RecordMember, index: u32) -> *mut *mut ConsumedRecord {
        let f = fixture(member);
        assert_eq!(((*f).stage, index), (0, 0));
        (*f).stage = 1;
        (*member).vtable = &REMOVAL;
        addr_of_mut!((*f).slot)
    }
    unsafe extern "C" fn wrong_remove(_: *mut RecordMember, _: u32) { panic!("stale member table"); }
    unsafe extern "C" fn remove(member: *mut RecordMember, index: u32) {
        let f = fixture(member);
        assert_eq!(((*f).stage, index), (1, 0));
        (*(*f).slot).value = (*(*f).slot).value.wrapping_add(1);
        (*f).slot = core::ptr::null_mut();
        (*f).stage = 2;
    }
    unsafe extern "C" fn first(owner: *mut RecordConsumer, kind: u32, resource: u32) {
        let f = owner.cast::<Fixture>();
        assert_eq!(((*f).stage, kind, resource), (2, 0x5374_7220, 0x36c3));
        (*f).stage = 3;
        (*owner).vtable = &SECOND;
    }
    unsafe extern "C" fn second(owner: *mut RecordConsumer, kind: u32, resource: u32) {
        let f = owner.cast::<Fixture>();
        assert_eq!(((*f).stage, kind, resource), (3, 0x5374_7220, 0x36c4));
        (*f).stage = 4;
    }
    static INITIAL: RecordMemberVTable = RecordMemberVTable {
        prefix: [0; 11], remove: wrong_remove, middle: [0; 4], get,
    };
    static REMOVAL: RecordMemberVTable = RecordMemberVTable {
        prefix: [0; 11], remove, middle: [0; 4], get,
    };
    static FIRST: RecordConsumerVTable = RecordConsumerVTable { prefix: [0; 22], dispatch: first };
    static SECOND: RecordConsumerVTable = RecordConsumerVTable { prefix: [0; 22], dispatch: second };

    #[test]
    fn saved_record_survives_slot_clear_and_tables_are_reloaded() {
        for value in [0, 0x7fff_ffff, u32::MAX] {
            let mut record = ConsumedRecord { opaque: [17, 23], value };
            let saved = &mut record as *mut ConsumedRecord;
            let mut f = Fixture {
                owner: RecordConsumer { vtable: &FIRST, opaque: [0xa5a5a5a5; 61],
                    cached_value: 99, member: RecordMember { vtable: &INITIAL } },
                slot: saved, stage: 0,
            };
            let owner = &mut f.owner as *mut RecordConsumer;
            unsafe { consume_with(owner, |deleted| {
                assert_eq!(deleted, saved.cast());
                assert_eq!(f.stage, 4);
                assert_eq!(f.owner.cached_value, value.wrapping_add(1));
                assert!(f.slot.is_null());
                f.stage = 5;
            }); }
            assert_eq!(f.stage, 5);
            assert_eq!(f.owner.opaque, [0xa5a5a5a5; 61]);
            assert_eq!(record.opaque, [17, 23]);
        }
    }
}

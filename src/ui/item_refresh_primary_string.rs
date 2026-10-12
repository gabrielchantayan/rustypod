//! Primary item string refresh — FUN_080443b4 @ 0x080443b4.
//! Raw extent [0x080443b4,0x08044410): 92 bytes, no literals, followed
//! by an independent PUSH. Two incoming plain BLs (0x08067c10,0x08095cfc),
//! three outgoing plain BLs, and no incoming or outgoing predicated BLs.
//! Look up id +0x2c in owner+0x118, ignore status, logically halve the
//! encoded byte length, validate with flags 0x1d, and replace flag bit 4
//! at +0x15 before refreshing the derived string through 0x080dca4c.
//! Preserve that helper's r0 result, which Ghidra's void signature omits.
//! Deviations: initialize scratch outputs overwritten by lookup; repr(C)
//! widens only the owner pointer on hosts. The unported derived-string
//! helper remains a typed resident call, replaceable on hosts, not a fake
//! implementation. Both other callees reuse their canonical Rust ports.

use core::ptr;
use crate::app::indexed_payload_lookup::indexed_payload_lookup_mode_one;
use crate::util::counted_wstr_validate::counted_wstr_validate;

/// Retail prefix through the primary and derived string ids (+0x2c/+0x30).
#[repr(C)]
pub struct PrimaryStringItem {
    pub owner: *mut u8,
    pub state: [u32; 10],
    pub string_id: i32,
    pub derived_string_id: i32,
}

pub type RefreshDerivedString = unsafe extern "C" fn(*mut PrimaryStringItem) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn resident_refresh_derived_string(item: *mut PrimaryStringItem) -> u32 {
    let refresh: RefreshDerivedString = core::mem::transmute(0x080dca4cusize);
    refresh(item)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn resident_refresh_derived_string(_: *mut PrimaryStringItem) -> u32 {
    panic!("primary string refresh requires resident helper 0x080dca4c")
}

/// Host boundary for the verified resident derived-string refresh helper.
/// Replace only while no refresh is running; restore after use.
pub static mut ITEM_REFRESH_DERIVED_STRING: RefreshDerivedString = resident_refresh_derived_string;

/// Refresh primary validation state, then refresh the dependent string.
///
/// # Safety
/// `item` and its owner index at +0x118 must satisfy indexed lookup and
/// resident derived-string refresh contracts, including the full retail
/// object storage required by the resident helper on target.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn item_refresh_primary_string(item: *mut PrimaryStringItem) -> u32 {
    let mut payload = ptr::null_mut();
    let mut byte_length = 0;
    indexed_payload_lookup_mode_one(
        (*item).owner.add(0x118), (*item).string_id as u32,
        &mut payload, &mut byte_length,
    );
    let valid = counted_wstr_validate(payload.cast(), (byte_length >> 1) as i32, 0x1d);
    let flag = ptr::addr_of_mut!((*item).state).cast::<u8>().add(17);
    flag.write((flag.read() & !0x10) | ((valid as u8 & 1) << 4));
    ptr::read_volatile(ptr::addr_of!(ITEM_REFRESH_DERIVED_STRING))(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::crts_tag::CRTS_TAG;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe extern "C" fn refresh(item: *mut PrimaryStringItem) -> u32 {
        // The dependent refresh must observe updated validation state,
        // and its writes must survive the wrapper's return.
        assert_eq!((*item).state[4] & 0x1000, 0);
        (*item).derived_string_id = -7;
        (*item).state[4] |= 0x1000;
        1
    }

    #[test]
    fn empty_and_invalid_ids_update_before_dependent_refresh() {
        let _lock = LOCK.lock();
        let mut owner = [0u32; 128];
        unsafe {
            let old = ITEM_REFRESH_DERIVED_STRING;
            ITEM_REFRESH_DERIVED_STRING = refresh;
            for tag in [0, CRTS_TAG] {
                owner[0x118 / 4] = tag;
                for id in [0, 1, -1, i32::MIN, i32::MAX] {
                    for flags in 0u8..=255 {
                        let mut item = PrimaryStringItem {
                            owner: owner.as_mut_ptr().cast(), state: [0xa5a5_a5a5; 10],
                            string_id: id, derived_string_id: 42,
                        };
                        ptr::addr_of_mut!(item.state).cast::<u8>().add(17).write(flags);
                        let mut expected = item.state;
                        expected[4] |= 0x1000;
                        assert_eq!(item_refresh_primary_string(&mut item), 1);
                        assert_eq!(item.state, expected);
                        assert_eq!(item.string_id, id);
                        assert_eq!(item.derived_string_id, -7);
                        assert_eq!(item.owner, owner.as_mut_ptr().cast());
                    }
                }
            }
            ITEM_REFRESH_DERIVED_STRING = old;
        }
    }
}

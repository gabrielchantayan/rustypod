//! Indexed item string flag refresh — FUN_08044360 @ 0x08044360.
//! True extent [0x08044360,0x080443b4): 84 bytes, no literals; the next
//! independent function begins with push {r2,r3,r4,lr}.
//! Raw aligned A32 decoding finds two incoming plain BLs (0x08067be4,
//! 0x08095cb0), two outgoing plain BLs (0x0804437c,0x08044394), and no
//! predicated incoming or outgoing BLs. Look up id +0x34 in owner+0x1c8,
//! ignore status, logically halve byte length, validate with flags 0x1d,
//! and replace only bit 6 at +0x15. Validator bit 2 forces rejection;
//! retain the lookup and validator calls rather than a constant bit clear.
//! Deviations: initialize scratch outputs overwritten by lookup; repr(C)
//! widens the owner pointer on hosts while retaining retail offsets on ARM.
//! Ghidra's extra arguments are scratch output storage, not inputs.

use core::ptr;
use crate::app::indexed_payload_lookup::indexed_payload_lookup_mode_one;
use crate::util::counted_wstr_validate::counted_wstr_validate;

/// Retail item prefix through the indexed string id at target offset +0x34.
#[repr(C)]
pub struct IndexedStringItem {
    pub owner: *mut u8,
    pub state: [u32; 12],
    pub string_id: i32,
}

/// Refresh bit 6 without changing any other item state.
///
/// # Safety
/// `item` must be writable and owner+0x1c8 must satisfy the indexed payload
/// lookup contract for the item's string id.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn item_refresh_indexed_string_flag(item: *mut IndexedStringItem) {
    let mut payload = ptr::null_mut();
    let mut byte_length = 0;
    indexed_payload_lookup_mode_one(
        (*item).owner.add(0x1c8), (*item).string_id as u32,
        &mut payload, &mut byte_length,
    );
    let valid = counted_wstr_validate(payload.cast(), (byte_length >> 1) as i32, 0x1d);
    let flag = ptr::addr_of_mut!((*item).state).cast::<u8>().add(17);
    flag.write((flag.read() & !0x40) | ((valid as u8 & 1) << 6));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::crts_tag::CRTS_TAG;

    #[test]
    fn empty_and_failed_lookups_clear_only_bit_six() {
        let mut owner = [0u32; 160];
        for tag in [0, CRTS_TAG] {
            owner[0x1c8 / 4] = tag;
            for id in [0, 1, -1, i32::MIN, i32::MAX] {
                for flags in 0u8..=255 {
                    let mut item = IndexedStringItem {
                        owner: owner.as_mut_ptr().cast(), state: [0xa5a5_a5a5; 12], string_id: id,
                    };
                    unsafe {
                        ptr::addr_of_mut!(item.state).cast::<u8>().add(17).write(flags);
                        let before = item.state;
                        item_refresh_indexed_string_flag(&mut item);
                        let mut expected = before;
                        expected[4] &= !0x4000;
                        assert_eq!(item.state, expected);
                    }
                    assert_eq!(item.string_id, id);
                    assert_eq!(item.owner, owner.as_mut_ptr().cast());
                }
            }
        }
    }
}

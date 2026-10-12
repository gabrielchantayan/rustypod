//! Item string flag refresh — FUN_080444d4 @ 0x080444d4.
//! True extent [0x080444d4,0x08044528): 84 bytes, no literals; the next
//! function begins with push {r2-r8,lr}. Raw aligned A32 decoding verifies
//! two incoming plain BLs (0x08067c90,0x08095c7c), no predicated incoming
//! BLs, two outgoing plain BLs, and no predicated outgoing BLs.
//! Look up item.string_id in owner+0xc0, ignore status, halve the returned
//! byte length, validate UTF-16 with flags 0x1d, and replace bit 3 at +0x15.
//! Flags include the validator's unconditional rejection bit; retain both
//! calls rather than replacing the algorithm with a constant bit clear.
//! Deviations: reuse both ported callees, initialize scratch outputs (the
//! lookup overwrites them), and use repr(C) host pointer widening. Ghidra's
//! extra arguments are scratch-register contents, not meaningful inputs.

use core::ptr;
use super::item_store_counted_string::CountedStringItem;
use crate::app::indexed_payload_lookup::indexed_payload_lookup_mode_one;
use crate::util::counted_wstr_validate::counted_wstr_validate;

/// Refresh the derived string flag without changing any other item state.
///
/// # Safety
/// `item` must be writable and its owner+0xc0 index must satisfy the indexed
/// lookup contract. Its string id must designate a valid lookup or error path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn item_refresh_string_flag(item: *mut CountedStringItem) {
    let mut payload = ptr::null_mut();
    let mut byte_length = 0;
    indexed_payload_lookup_mode_one(
        (*item).owner.add(0xc0), (*item).string_id as u32,
        &mut payload, &mut byte_length,
    );
    let valid = counted_wstr_validate(payload.cast(), (byte_length >> 1) as i32, 0x1d);
    // Target +0x15 is byte 17 of the state array after the owner pointer.
    let flag = ptr::addr_of_mut!((*item).state).cast::<u8>().add(17);
    flag.write((flag.read() & !8) | ((valid as u8 & 1) << 3));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::crts_tag::CRTS_TAG;

    #[test]
    fn empty_and_failed_lookups_clear_only_bit_three() {
        let mut owner = [0u32; 64];
        for tag in [0, CRTS_TAG] {
            owner[0xc0 / 4] = tag;
            for id in [0, 1, -1, i32::MIN, i32::MAX] {
                for flags in 0u8..=255 {
                    let mut item = CountedStringItem {
                        owner: owner.as_mut_ptr().cast(), state: [0xa5a5_a5a5; 9], string_id: id,
                    };
                    unsafe {
                        let bytes = ptr::addr_of_mut!(item.state).cast::<u8>();
                        bytes.add(17).write(flags);
                        let before = item.state;
                        item_refresh_string_flag(&mut item);
                        let mut expected = before;
                        expected[4] &= !0x800;
                        assert_eq!(item.state, expected);
                    }
                    assert_eq!(item.string_id, id);
                    assert_eq!(item.owner, owner.as_mut_ptr().cast());
                }
            }
        }
    }
}

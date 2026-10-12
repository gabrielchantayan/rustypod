//! Secondary item string flag refresh — FUN_08044480 @ 0x08044480.
//! True extent [0x08044480,0x080444d4): 84 bytes, no literals; the next
//! function begins with push {r2,r3,r4,lr}. Raw aligned A32 decoding finds
//! two incoming plain BLs (0x08067c3c,0x08095d4c), no predicated incoming
//! BLs, two outgoing plain BLs, and no predicated outgoing BLs.
//! Look up the string id at +0x40 in owner+0x278, ignore lookup status,
//! halve the returned byte length, validate with flags 0x1d, and replace
//! only bit 7 of the byte at +0x15. Validator flag bit 2 forces rejection;
//! retain both calls rather than reducing the algorithm to a bit clear.
//! Deviations: initialize scratch outputs overwritten by lookup, reuse
//! ported callees, and widen the owner pointer on hosts through repr(C).
//! Ghidra's extra arguments are saved scratch registers, not inputs.
//! Verification: 15,750 host tests pass; a standalone real-library smoke
//! clears a failed lookup's flag byte from 0xa5 to 0x25 with neighbors intact.
//! ARM release and match.py retain both callee relocations, +0x40 id,
//! owner+0x278, logical halving, and +0x15 flag access (23 vs 21 instructions;
//! LLVM adds frame setup and initialized scratch slots).

use core::ptr;
use crate::app::indexed_payload_lookup::indexed_payload_lookup_mode_one;
use crate::util::counted_wstr_validate::counted_wstr_validate;

/// Retail item prefix through its secondary string id at target offset 0x40.
#[repr(C)]
pub struct SecondaryStringItem {
    pub owner: *mut u8,
    pub state: [u32; 15],
    pub string_id: i32,
}

/// Refresh the secondary string flag, preserving all other item state.
///
/// # Safety
/// `item` must be writable and its owner+0x278 index must satisfy the
/// indexed payload lookup contract for the item's string id.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn item_refresh_secondary_string_flag(item: *mut SecondaryStringItem) {
    let mut payload = ptr::null_mut();
    let mut byte_length = 0;
    indexed_payload_lookup_mode_one(
        (*item).owner.add(0x278), (*item).string_id as u32,
        &mut payload, &mut byte_length,
    );
    let valid = counted_wstr_validate(payload.cast(), (byte_length >> 1) as i32, 0x1d);
    let flag = ptr::addr_of_mut!((*item).state).cast::<u8>().add(17);
    flag.write((flag.read() & !0x80) | ((valid as u8 & 1) << 7));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::crts_tag::CRTS_TAG;

    #[test]
    fn empty_and_failed_lookups_clear_only_bit_seven() {
        let mut owner = [0u32; 192];
        for tag in [0, CRTS_TAG] {
            owner[0x278 / 4] = tag;
            for id in [0, 1, -1, i32::MIN, i32::MAX] {
                for flags in 0u8..=255 {
                    let mut item = SecondaryStringItem {
                        owner: owner.as_mut_ptr().cast(), state: [0xa5a5_a5a5; 15], string_id: id,
                    };
                    unsafe {
                        ptr::addr_of_mut!(item.state).cast::<u8>().add(17).write(flags);
                        let before = item.state;
                        item_refresh_secondary_string_flag(&mut item);
                        let mut expected = before;
                        expected[4] &= !0x8000;
                        assert_eq!(item.state, expected);
                    }
                    assert_eq!(item.string_id, id);
                    assert_eq!(item.owner, owner.as_mut_ptr().cast());
                }
            }
        }
    }
}

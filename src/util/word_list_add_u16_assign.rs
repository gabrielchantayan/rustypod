//! `word_list_add_u16_assign` — original: `FUN_082d3e5c` @ 0x082d3e5c.
//!
//! Raw extent: 140 bytes (35 ARM words), from 0x082d3e5c through 0x082d3ee4;
//! the next real function starts with `push {r0-r11,lr}` at 0x082d3ee8. The
//! body has one plain `bl` to [`word_list_is_zero`] and no predicated `bl`
//! instructions. Complete-image ARM branch decoding finds no direct inbound
//! `bl` instructions; the four Ghidra xrefs reach it by non-BL control flow.
//!
//! Adds `value` to the little-endian [`WordList`] in place, propagating the
//! carry across its active words and appending it when needed. An all-zero
//! list delegates to `word_list_assign_value`, exactly matching the original
//! tail branch after its explicit low-16-bit zero extension. No deliberate
//! deviations.

use super::word_list::WordList;
use super::word_list_assign_value::word_list_assign_value;
use super::word_list_is_zero::word_list_is_zero;

/// Adds a 16-bit value to `list` in place.
///
/// # Safety
///
/// `list` must name a writable [`WordList`] whose entries buffer holds every
/// active word and one additional word if the addition emits a final carry.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_add_u16_assign(value: u16, list: *mut WordList) {
    if word_list_is_zero(list) != 0 {
        word_list_assign_value(value as u32, list);
        return;
    }

    let count = (*list).count;
    let entries = (*list).entries;
    let mut carry = value as u32;
    let mut index = 0usize;

    while index < count as usize && carry != 0 {
        let (sum, next_carry) = (*entries.add(index)).overflowing_add(carry);
        *entries.add(index) = sum;
        carry = next_carry as u32;
        index += 1;
    }

    if carry != 0 {
        (*list).count = count.wrapping_add(1);
        *entries.add(count as usize) = carry;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::word_list_add_u16_assign;
    use crate::util::word_list::WordList;

    fn list(entries: &mut [u32], count: u16) -> WordList {
        WordList {
            count,
            capacity: entries.len() as u16,
            entries: entries.as_mut_ptr(),
        }
    }

    #[test]
    fn assigns_zero_list_without_reading_existing_storage() {
        let mut entries = [0, 0, 0xfeed_face];
        let mut value = list(&mut entries, 2);

        unsafe { word_list_add_u16_assign(0x1234, &mut value) };

        assert_eq!(value.count, 1);
        assert_eq!(entries, [0x1234, 0, 0xfeed_face]);
    }

    #[test]
    fn zero_value_preserves_nonzero_list() {
        let mut entries = [0, 0x20, 0xdead_beef];
        let mut value = list(&mut entries, 2);

        unsafe { word_list_add_u16_assign(0, &mut value) };

        assert_eq!(value.count, 2);
        assert_eq!(entries, [0, 0x20, 0xdead_beef]);
    }

    #[test]
    fn propagates_carry_through_active_words_and_appends() {
        let mut entries = [0xffff_ffff, 0xffff_ffff, 0xdead_beef];
        let mut value = list(&mut entries, 2);

        unsafe { word_list_add_u16_assign(1, &mut value) };

        assert_eq!(value.count, 3);
        assert_eq!(entries, [0, 0, 1]);
    }

    #[test]
    fn stops_after_carry_is_absorbed() {
        let mut entries = [0xffff_ffff, 7, 0xdead_beef];
        let mut value = list(&mut entries, 2);

        unsafe { word_list_add_u16_assign(1, &mut value) };

        assert_eq!(value.count, 2);
        assert_eq!(entries, [0, 8, 0xdead_beef]);
    }
}

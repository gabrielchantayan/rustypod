//! Upper-bound search over sorted 12-byte StringObjectWord records.

use super::string_object::StringObject;
use super::string_object_less::string_object_less;
use super::templates::StringObjectWord;

/// `string_object_word_upper_bound` — originals: `FUN_083e7dd8` @
/// `0x083e7dd8` and byte-identical `FUN_083e7e48` @ `0x083e7e48`.
///
/// Raw `osos.dec` establishes the exact **112-byte** extent for the assigned
/// copy, `0x083e7dd8..0x083e7e47`: it returns with `pop {r2-r8,pc}`, and the
/// next independently linked function begins with `push {r2-r8,lr}` at
/// `0x083e7e48`. The body has two plain unconditional direct `bl` calls
/// (`__rt_sdiv` @ `0x08031568` and `string_object_less` @ `0x083d6550`) and
/// no predicated direct `bl` calls. The following 112-byte copy at
/// `0x083e7e48` has the same words, so both hook addresses deliberately share
/// this one symbol.
///
/// Searches `[first, last)` for the first record strictly greater than `key`.
/// Each iteration divides the remaining count by two with signed truncation,
/// asks the stateless comparator whether `key < middle.string`, and retains the
/// lower or upper half accordingly. Equal keys therefore advance past the
/// equal run.
///
/// Deliberate deviations: typed cursor arithmetic replaces the raw `+0xc`
/// address calculations and native count division replaces the ADS helper;
/// both preserve the record stride and quotient for valid vector ranges.
///
/// # Safety
///
/// `[first, last)` must be a readable contiguous range of sorted
/// [`StringObjectWord`] records. `key` must be a readable [`StringObject`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_word_upper_bound(
    mut first: *const StringObjectWord,
    last: *const StringObjectWord,
    key: *const StringObject,
    comparator: *const u8,
) -> *const StringObjectWord {
    let mut count = last.offset_from(first);

    while count > 0 {
        let half = count / 2;
        let middle = first.offset(half);
        if string_object_less(comparator, key, core::ptr::addr_of!((*middle).string)) {
            count = half;
        } else {
            first = middle.add(1);
            count -= half + 1;
        }
    }

    first
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(payload: *mut u8, trailing_word: u32) -> StringObjectWord {
        StringObjectWord {
            string: StringObject {
                vtable: core::ptr::null(),
                payload,
            },
            trailing_word,
        }
    }

    #[test]
    fn finds_upper_bound_at_empty_between_and_duplicate_runs() {
        let mut apple = *b"apple\0";
        let mut banana = *b"banana\0";
        let mut blueberry = *b"blueberry\0";
        let mut carrot = *b"carrot\0";
        let mut records = [
            record(apple.as_mut_ptr(), 1),
            record(banana.as_mut_ptr(), 2),
            record(banana.as_mut_ptr(), 3),
            record(carrot.as_mut_ptr(), 4),
        ];
        let empty: [StringObjectWord; 0] = [];
        let banana_key = record(banana.as_mut_ptr(), 0);
        let apple_key = record(apple.as_mut_ptr(), 0);
        let blueberry_key = record(blueberry.as_mut_ptr(), 0);
        let carrot_key = record(carrot.as_mut_ptr(), 0);

        unsafe {
            assert_eq!(
                string_object_word_upper_bound(empty.as_ptr(), empty.as_ptr(), &banana_key.string, core::ptr::null()),
                empty.as_ptr(),
            );
            assert_eq!(
                string_object_word_upper_bound(records.as_ptr(), records.as_ptr().add(records.len()), &apple_key.string, core::ptr::null()),
                records.as_ptr().add(1),
            );
            assert_eq!(
                string_object_word_upper_bound(records.as_ptr(), records.as_ptr().add(records.len()), &banana_key.string, core::ptr::null()),
                records.as_ptr().add(3),
            );
            assert_eq!(
                string_object_word_upper_bound(records.as_ptr(), records.as_ptr().add(records.len()), &blueberry_key.string, core::ptr::null()),
                records.as_ptr().add(3),
            );
            assert_eq!(
                string_object_word_upper_bound(records.as_ptr(), records.as_ptr().add(records.len()), &carrot_key.string, core::ptr::null()),
                records.as_ptr().add(records.len()),
            );
        }
    }
}

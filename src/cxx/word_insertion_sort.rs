//! Guarded word insertion sort from retailOS.
//!
//! `FUN_083e8378` @ `0x083e8378`: true size 120 bytes, ending at
//! `0x083e83f0`, the next real function's PUSH. Raw A32 decoding finds one
//! incoming plain BL at `0x083ea748`, zero predicated incoming BLs, one
//! outgoing plain BL at `0x083e83dc`, zero predicated outgoing BLs, and one
//! indirect comparator BLX at `0x083e83a4`.
//!
//! For each word after the first, compare it with the first word. A nonzero
//! result shifts the entire prefix right and installs a new first word;
//! otherwise the existing unguarded insertion helper inserts it into the
//! sorted prefix, using the first word as its stopping sentinel.
//! No behavioral deviations; the callee is the existing Rust port of
//! `0x083e9aec`, not a new retail-address seam. Prefix shifts use volatile
//! word accesses to prevent LLVM from replacing the loop with a libc call.

use super::word_insertion_sort_insert::{word_insertion_sort_insert, WordOrder};

/// # Safety
/// `first..last` must be an aligned, writable contiguous word range (or equal
/// pointers for an empty range). `comparator` must implement a strict ordering,
/// returning nonzero when its first value precedes its second, and must not
/// mutate the range. No sentinel outside the range is required.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn word_insertion_sort(first: *mut u32, last: *mut u32, comparator: WordOrder) {
    if first == last {
        return;
    }
    let mut current = first.add(1);
    while current != last {
        let value = current.read();
        if comparator(value, first.read()) != 0 {
            let mut destination = current;
            while destination != first {
                let prior = destination.sub(1);
                destination.write_volatile(prior.read_volatile());
                destination = prior;
            }
            first.write(value);
        } else {
            word_insertion_sort_insert(current, value, comparator);
        }
        current = current.add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    unsafe extern "C" fn ascending(a: u32, b: u32) -> i32 { if a < b { -7 } else { 0 } }
    unsafe extern "C" fn descending(a: u32, b: u32) -> i32 { if a > b { 9 } else { 0 } }
    unsafe extern "C" fn by_key(a: u32, b: u32) -> i32 { i32::from((a >> 16) < (b >> 16)) }
    unsafe extern "C" fn forbidden(_: u32, _: u32) -> i32 { panic!("unexpected comparison") }

    #[test]
    fn empty_and_singleton_never_compare() {
        unsafe { word_insertion_sort(core::ptr::null_mut(), core::ptr::null_mut(), forbidden) };
        let mut word = u32::MAX;
        unsafe { word_insertion_sort(&mut word, (&mut word as *mut u32).add(1), forbidden) };
        assert_eq!(word, u32::MAX);
    }

    #[test]
    fn all_short_sequences_match_reference_in_both_orders() {
        let alphabet = [0, 1, 0x8000_0000, u32::MAX];
        for len in 0..=6 {
            for mut encoding in 0..4usize.pow(len as u32) {
                let mut input = std::vec::Vec::new();
                for _ in 0..len {
                    input.push(alphabet[encoding % 4]);
                    encoding /= 4;
                }
                for (compare, reverse) in [(ascending as WordOrder, false), (descending as WordOrder, true)] {
                    let mut expected = input.clone();
                    expected.sort();
                    if reverse { expected.reverse(); }
                    let mut guarded = std::vec![0x1234_5678];
                    guarded.extend_from_slice(&input);
                    guarded.push(0x8765_4321);
                    unsafe {
                        let first = guarded.as_mut_ptr().add(1);
                        word_insertion_sort(first, first.add(len), compare);
                    }
                    assert_eq!(&guarded[1..1 + len], expected.as_slice());
                    assert_eq!(guarded[0], 0x1234_5678);
                    assert_eq!(guarded[len + 1], 0x8765_4321);
                }
            }
        }
    }

    #[test]
    fn equivalent_keys_preserve_original_order() {
        let mut words = [0x20001, 0x10002, 0x20003, 0x00004, 0x10005, 0x00006];
        unsafe { word_insertion_sort(words.as_mut_ptr(), words.as_mut_ptr().add(words.len()), by_key) };
        assert_eq!(words, [0x00004, 0x00006, 0x10002, 0x10005, 0x20001, 0x20003]);
    }
}

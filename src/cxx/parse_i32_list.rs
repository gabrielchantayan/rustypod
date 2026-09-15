//! `parse_i32_list` — original: `FUN_081fa86c` @ **0x081fa86c**.
//!
//! **136 bytes**, 0x081fa86c..0x081fa8f0: the `pop {r4,r5,pc}` at
//! 0x081fa8ec is followed by the independently linked `push {r3-r8,lr}` at
//! 0x081fa8f0. Raw `osos.dec` decoding finds **7 plain `bl` instructions**
//! (two to `tokenizer_next`; one each to construction, initialization, parse,
//! append, and vector size), zero predicated `bl` instructions, and one
//! predicated `bne`.
//!
//! Constructs `out` as an observable array, splits the UTF-16 `range` at
//! commas with quote-aware tokenization, parses every token as a signed i32,
//! and appends the resulting word in order. `context` is passed by all five
//! callers but the raw body never reads r1.
//!
//! Deliberate deviation: none on target. Host tests inject the already-ported
//! parser and array operations because their target-width object models cannot
//! compose through a native vtable pointer.

use crate::cxx::observable_array::{observable_array_append, observable_array_construct, ObservableArray};
use crate::cxx::tokenizer::{tokenizer_init, tokenizer_next, Tokenizer};
use crate::strto::range_i32::parse_i32_utf16_range;

#[inline(always)]
unsafe fn token_is_nonempty(token: *const u32) -> bool {
    #[cfg(not(test))]
    {
        crate::cxx::templates::vector_size_elem2_clamped(token.cast()) != 0
    }
    #[cfg(test)]
    {
        token.read() < token.add(1).read()
    }
}

/// Splits a UTF-16 comma-separated list into signed decimal values.
///
/// # Safety
///
/// `out` must point to writable [`ObservableArray`] storage. `range` must
/// point to a two-word `{begin, end}` UTF-16 range, and each referenced token
/// must satisfy [`parse_i32_utf16_range`]'s input contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parse_i32_list(
    out: *mut ObservableArray,
    _context: *mut u8,
    range: *const u8,
) {
    #[cfg(test)]
    let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PARSE_I32_LIST_OPS)) };

    #[cfg(not(test))]
    let array = unsafe { observable_array_construct(out) };
    #[cfg(test)]
    let array = unsafe { (ops.construct)(out) };

    let mut tokenizer = core::mem::MaybeUninit::<Tokenizer>::uninit();
    unsafe {
        tokenizer_init(tokenizer.as_mut_ptr(), range.cast(), b',' as u16, i32::MAX, 1);
    }

    let mut token = [0u32; 2];
    unsafe { tokenizer_next(token.as_mut_ptr(), tokenizer.as_mut_ptr()) };
    while unsafe { token_is_nonempty(token.as_ptr()) } {
        #[cfg(not(test))]
        let mut value = unsafe { parse_i32_utf16_range(token.as_ptr().cast()) };
        #[cfg(test)]
        let mut value = unsafe { (ops.parse)(token.as_ptr().cast()) };
        #[cfg(not(test))]
        unsafe { observable_array_append(array, core::ptr::addr_of_mut!(value).cast()) };
        #[cfg(test)]
        unsafe { (ops.append)(array, core::ptr::addr_of_mut!(value).cast()) };
        unsafe { tokenizer_next(token.as_mut_ptr(), tokenizer.as_mut_ptr()) };
    }
}

#[cfg(test)]
type Construct = unsafe extern "C" fn(*mut ObservableArray) -> *mut ObservableArray;
#[cfg(test)]
type Parse = unsafe extern "C" fn(*const u8) -> i32;
#[cfg(test)]
type Append = unsafe extern "C" fn(*mut ObservableArray, *mut u8) -> u32;

#[cfg(test)]
#[derive(Clone, Copy)]
struct ParseI32ListOps { construct: Construct, parse: Parse, append: Append }

#[cfg(test)]
unsafe extern "C" fn default_construct(out: *mut ObservableArray) -> *mut ObservableArray {
    observable_array_construct(out)
}
#[cfg(test)]
unsafe extern "C" fn default_parse(range: *const u8) -> i32 { parse_i32_utf16_range(range) }
#[cfg(test)]
unsafe extern "C" fn default_append(array: *mut ObservableArray, value: *mut u8) -> u32 {
    observable_array_append(array, value)
}
#[cfg(test)]
static mut PARSE_I32_LIST_OPS: ParseI32ListOps = ParseI32ListOps {
    construct: default_construct, parse: default_parse, append: default_append,
};

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Mutex;
    use std::vec::Vec;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut VALUES: Vec<i32> = Vec::new();

    unsafe extern "C" fn construct(out: *mut ObservableArray) -> *mut ObservableArray { out }
    unsafe extern "C" fn parse(range: *const u8) -> i32 {
        let words = range.cast::<u32>();
        let mut value = 0i32;
        let mut p = words.read() as *const u16;
        let end = words.add(1).read() as *const u16;
        while p != end {
            value = value.wrapping_mul(10).wrapping_add(p.read() as i32 - '0' as i32);
            p = p.add(1);
        }
        value
    }
    unsafe extern "C" fn append(_array: *mut ObservableArray, value: *mut u8) -> u32 {
        core::ptr::addr_of_mut!(VALUES).as_mut().unwrap().push(value.cast::<i32>().read());
        0
    }
    struct Guard(ParseI32ListOps);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(PARSE_I32_LIST_OPS).write_volatile(self.0) }
        }
    }
    fn install() -> Guard {
        unsafe {
            let old = core::ptr::addr_of!(PARSE_I32_LIST_OPS).read_volatile();
            core::ptr::addr_of_mut!(PARSE_I32_LIST_OPS).write_volatile(ParseI32ListOps { construct, parse, append });
            Guard(old)
        }
    }
    #[test]
    fn parses_comma_delimited_utf16_values_in_order() {
        let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _ops = install();
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::PARSE_I32_LIST, 0x1000) else {
            crate::testing::note_missing_u32_fixture("cxx::parse_i32_list");
            return;
        };
        let input = slab.cast::<u16>();
        unsafe {
            [b'1' as u16, b'2' as u16, b',' as u16, b'0' as u16, b',' as u16, b'7' as u16].iter().enumerate().for_each(|(i, &value)| input.add(i).write(value));
            let range = [input as usize as u32, input.add(6) as usize as u32];
            core::ptr::addr_of_mut!(VALUES).as_mut().unwrap().clear();
            parse_i32_list(core::ptr::null_mut(), core::ptr::null_mut(), range.as_ptr().cast());
            assert_eq!(VALUES.as_slice(), &[12, 0, 7]);
        }
    }
    #[test]
    fn does_not_parse_empty_or_inverted_ranges() {
        let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _ops = install();
        for range in [[1u32, 1], [2, 1]] {
            unsafe {
                core::ptr::addr_of_mut!(VALUES).as_mut().unwrap().clear();
                parse_i32_list(core::ptr::null_mut(), core::ptr::null_mut(), range.as_ptr().cast());
                assert!(VALUES.is_empty());
            }
        }
    }
}

//! `tokenizer_next_string` — original: `FUN_081e8768` @ `0x081e8768`
//! (**36 bytes**, `0x081e8768..0x081e878c`; the independently linked
//! constructor opens at `0x081e878c` with `push {r4, lr}`). **4 plain inbound
//! `bl` call sites, 0 predicated**, verified by decoding every direct branch in
//! `osos.dec`; the body itself makes two plain calls, to `tokenizer_next` and
//! `string_from_range`.
//!
//! Takes the next UTF-16 range from the tokenizer embedded at +0x14 in a
//! reader object, then materializes that range into the output StringObject.
//! The range is intentionally a private two-word stack pair, as in the ARM
//! body: `tokenizer_next(&pair, reader + 0x14)` followed by
//! `string_from_range(out, &pair)`.
//!
//! # Deliberate deviations
//!
//! `tokenizer_next` is already ported and called directly. `string_from_range`
//! @ 0x080f020c remains unported, so this uses the established `RANGE_I32_OPS`
//! volatile seam rather than inventing a second converter boundary.

use core::mem::MaybeUninit;
use crate::cxx::string_object::StringObject;
use crate::cxx::tokenizer::{tokenizer_next, Tokenizer};
use crate::strto::range_i32::{RangeI32Ops, RANGE_I32_OPS};

/// The reader prefix consumed by [`tokenizer_next_string`].
///
/// The constructor at 0x081e878c initializes the opaque five-word prefix and
/// then constructs the [`Tokenizer`] at +0x14. Its concrete prefix fields are
/// not read by this function.
#[repr(C)]
pub struct TokenizerStringReader {
    opaque_prefix: [u32; 5],
    tokenizer: Tokenizer,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(TokenizerStringReader, tokenizer)];

#[inline(always)]
unsafe fn range_converter_ops() -> RangeI32Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RANGE_I32_OPS)) }
}

/// tokenizer_next_string — original: `FUN_081e8768` @ `0x081e8768`.
///
/// Advances `reader`'s embedded tokenizer once, then passes its `{begin, end}`
/// pair to the UTF-16 range converter for materialization into `out`. Neither
/// pointer is checked, matching the original's direct calls.
///
/// # Safety
///
/// `out` must be writable, `reader` must contain a live [`Tokenizer`] at
/// +0x14, and that tokenizer's range must meet [`tokenizer_next`]'s contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tokenizer_next_string")]
#[inline(never)]
pub unsafe extern "C" fn tokenizer_next_string(
    out: *mut StringObject,
    reader: *mut TokenizerStringReader,
) {
    let mut range = MaybeUninit::<[u32; 2]>::uninit();
    unsafe {
        tokenizer_next(
            range.as_mut_ptr().cast(),
            core::ptr::addr_of_mut!((*reader).tokenizer),
        )
    };
    let converter = unsafe { range_converter_ops().string_from_range };
    unsafe { converter(out, range.as_ptr().cast()) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::strto::range_i32::RANGE_I32_OPS_TEST_LOCK;
    use core::ptr;
    use std::sync::{LazyLock, MutexGuard};

    static mut CONVERTER_CALLS: usize = 0;
    static mut CONVERTER_OUT: usize = 0;
    static mut CONVERTER_RANGE: usize = 0;
    static mut CONVERTER_WORDS: [u32; 2] = [0; 2];

    unsafe extern "C" fn converter_fixture(out: *mut StringObject, range: *const u8) {
        unsafe {
            CONVERTER_CALLS += 1;
            CONVERTER_OUT = out as usize;
            CONVERTER_RANGE = range as usize;
            CONVERTER_WORDS = range.cast::<u32>().cast::<[u32; 2]>().read();
        }
    }

    struct RangeOpsGuard(RangeI32Ops);

    impl Drop for RangeOpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(RANGE_I32_OPS).write_volatile(self.0) };
        }
    }

    fn install_converter() -> (MutexGuard<'static, ()>, RangeOpsGuard) {
        let lock = RANGE_I32_OPS_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let saved = core::ptr::addr_of!(RANGE_I32_OPS).read_volatile();
            core::ptr::addr_of_mut!(RANGE_I32_OPS).write_volatile(RangeI32Ops {
                string_from_range: converter_fixture,
                parse_decimal: saved.parse_decimal,
            });
            (lock, RangeOpsGuard(saved))
        }
    }

    fn reader(cursor: u32, end: u32, remaining: i32) -> TokenizerStringReader {
        TokenizerStringReader {
            opaque_prefix: [0; 5],
            tokenizer: Tokenizer {
                begin: cursor,
                end,
                delimiter: b',' as u16,
                pad_0a: 0,
                cursor,
                remaining,
                allow_quotes: 0,
            },
        }
    }

    fn try_slab() -> Option<*mut u16> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::TOKENIZER_NEXT_STRING,
                0x1000,
            )
            .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u16)
    }

    fn reset_converter() {
        unsafe {
            CONVERTER_CALLS = 0;
            CONVERTER_OUT = 0;
            CONVERTER_RANGE = 0;
            CONVERTER_WORDS = [u32::MAX; 2];
        }
    }

    #[test]
    fn converts_the_private_range_of_a_nonempty_token() {
        let (_lock, _ops) = install_converter();
        let Some(text) = try_slab() else {
            return;
        };
        unsafe {
            text.write(b'a' as u16);
            text.add(1).write(b',' as u16);
        }
        reset_converter();
        let base = text as usize as u32;
        let mut reader = reader(base, base + 4, 1);
        let mut out = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };

        unsafe { tokenizer_next_string(&mut out, &mut reader) };

        unsafe {
            assert_eq!(CONVERTER_CALLS, 1);
            assert_eq!(CONVERTER_OUT, (&mut out as *mut StringObject) as usize);
            assert_eq!(CONVERTER_WORDS, [base, base + 2]);
            assert_ne!(CONVERTER_RANGE, text as usize);
        }
        assert_eq!(reader.tokenizer.cursor, base + 4);
        assert_eq!(reader.tokenizer.remaining, 0);
    }

    #[test]
    fn converts_the_empty_pair_for_an_exhausted_tokenizer() {
        let (_lock, _ops) = install_converter();
        reset_converter();
        let mut reader = reader(0, 0x200, 7);
        let mut out = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };

        unsafe { tokenizer_next_string(&mut out, &mut reader) };

        unsafe {
            assert_eq!(CONVERTER_CALLS, 1);
            assert_eq!(CONVERTER_OUT, (&mut out as *mut StringObject) as usize);
            assert_eq!(CONVERTER_WORDS, [0, 0]);
            assert_ne!(CONVERTER_RANGE, (&mut reader.tokenizer.begin as *mut u32) as usize);
        }
        assert_eq!(reader.tokenizer.cursor, 0, "exhausted state remains untouched");
        assert_eq!(reader.tokenizer.remaining, 7);
    }
}

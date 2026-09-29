//! `opaque_handle_result_query` — original: `FUN_082e8248` @ 0x082e8248
//! (**88 bytes**; two inbound plain `bl` call sites and zero predicated `bl`
//! call sites).
//!
//! Raw `osos.dec` establishes the exact body from 0x082e8248 through the
//! `bx lr` at 0x082e829c. The following word, 0x50544852, is this object's
//! `RHTP` magic literal; 0x082e82a4 begins the next real function. The two
//! inbound calls are plain `bl` instructions at 0x08262020 and 0x08262050;
//! this leaf has no outbound calls.
//!
//! Algorithm: validate a non-null opaque handle by its `RHTP` header word,
//! require both output pointers, then return status 7 if its signed +0x18c
//! count is non-positive. Otherwise copy its +0x214 and +0x220 result words
//! to the second and third arguments and return zero. Invalid handles or
//! output pointers return 0x1a. Deliberate deviations: the target's fixed
//! 32-bit layout is represented by word indices rather than a host pointer
//! layout; no behavior changes.

/// Opaque handle header word accepted by retailOS.
pub const RHTP_HANDLE_MAGIC: u32 = 0x5054_4852;
/// Retail status for an invalid handle or null output pointer.
pub const HANDLE_RESULT_INVALID: u32 = 0x1a;
/// Retail status when the handle has no positive result count.
pub const HANDLE_RESULT_UNAVAILABLE: u32 = 7;

const RESULT_COUNT_WORD: usize = 0x18c / 4;
const FIRST_RESULT_WORD: usize = 0x214 / 4;
const SECOND_RESULT_WORD: usize = 0x220 / 4;

/// Reads the two result words from an initialized opaque handle.
///
/// # Safety
/// `handle` must point to an object containing words through +0x220 whenever
/// it is non-null. Non-null outputs must be writable `u32` locations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_handle_result_query(
    handle: *const u32,
    first_result: *mut u32,
    second_result: *mut u32,
) -> u32 {
    if handle.is_null() || handle.read() != RHTP_HANDLE_MAGIC || first_result.is_null() || second_result.is_null() {
        return HANDLE_RESULT_INVALID;
    }

    if (handle.add(RESULT_COUNT_WORD).read() as i32) < 1 {
        return HANDLE_RESULT_UNAVAILABLE;
    }

    first_result.write(handle.add(FIRST_RESULT_WORD).read());
    second_result.write(handle.add(SECOND_RESULT_WORD).read());
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE_WORDS: usize = SECOND_RESULT_WORD + 1;

    #[test]
    fn rejects_null_bad_magic_and_missing_output_without_writes() {
        let mut handle = [0u32; HANDLE_WORDS];
        let mut first = 0x1111_1111;
        let mut second = 0x2222_2222;

        assert_eq!(unsafe { opaque_handle_result_query(core::ptr::null(), &mut first, &mut second) }, HANDLE_RESULT_INVALID);
        handle[0] = !RHTP_HANDLE_MAGIC;
        assert_eq!(unsafe { opaque_handle_result_query(handle.as_ptr(), &mut first, &mut second) }, HANDLE_RESULT_INVALID);
        handle[0] = RHTP_HANDLE_MAGIC;
        assert_eq!(unsafe { opaque_handle_result_query(handle.as_ptr(), core::ptr::null_mut(), &mut second) }, HANDLE_RESULT_INVALID);
        assert_eq!(unsafe { opaque_handle_result_query(handle.as_ptr(), &mut first, core::ptr::null_mut()) }, HANDLE_RESULT_INVALID);
        assert_eq!((first, second), (0x1111_1111, 0x2222_2222));
    }

    #[test]
    fn refuses_zero_and_negative_counts_without_writes() {
        let mut handle = [0u32; HANDLE_WORDS];
        handle[0] = RHTP_HANDLE_MAGIC;
        handle[FIRST_RESULT_WORD] = 0xaaaa_aaaa;
        handle[SECOND_RESULT_WORD] = 0xbbbb_bbbb;
        let mut first = 1;
        let mut second = 2;

        for count in [0, -1] {
            handle[RESULT_COUNT_WORD] = count as u32;
            assert_eq!(unsafe { opaque_handle_result_query(handle.as_ptr(), &mut first, &mut second) }, HANDLE_RESULT_UNAVAILABLE);
            assert_eq!((first, second), (1, 2));
        }
    }

    #[test]
    fn copies_both_result_words_for_a_positive_count() {
        let mut handle = [0u32; HANDLE_WORDS];
        handle[0] = RHTP_HANDLE_MAGIC;
        handle[RESULT_COUNT_WORD] = 1;
        handle[FIRST_RESULT_WORD] = 0x1234_5678;
        handle[SECOND_RESULT_WORD] = 0x9abc_def0;
        let mut first = 0;
        let mut second = 0;

        assert_eq!(unsafe { opaque_handle_result_query(handle.as_ptr(), &mut first, &mut second) }, 0);
        assert_eq!((first, second), (0x1234_5678, 0x9abc_def0));
    }
}

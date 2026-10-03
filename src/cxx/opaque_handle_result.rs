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

type HandleResultSet = unsafe extern "C" fn(*mut u32, u32, *const u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handle_result_set(_: *mut u32, _: u32, _: *const u32) -> u32 {
    panic!("install opaque-handle result setter host seam")
}

/// Host replacement for the verified retail setter at 0x082e8534.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_HANDLE_RESULT_SET: HandleResultSet = missing_handle_result_set;

/// Replaces the second result while preserving the queried first result.
///
/// Original `FUN_08262038` @ **0x08262038**, **56 bytes** through the pop
/// at 0x0826206c; the next function starts at 0x08262070. Verified outbound
/// calls: one plain BL to 0x082e8248 and one BLEQ to 0x082e8534. Two plain
/// inbound BLs (0x081939a8, 0x081939d0), zero predicated inbound calls.
///
/// Query the wrapper's handle into two stack words. On success, replace the
/// second word with `value`, reload the handle, and invoke the retail setter
/// with the preserved first word. Ignore both statuses; query failure skips
/// the setter. The setter validates mode/value, writes +0x214/+0x220, marks
/// +0x200 bits 0 and 1, and notifies the handle's backing object.
///
/// Deliberate deviations: initialize scratch words rather than copying the
/// caller's unspecified r2/r3; successful queries overwrite both before use.
/// Host wrapper pointers use native width; handle fields retain word indices.
/// The unported setter remains a direct firmware call, not a partial port.
///
/// # Safety
/// `wrapper` must point to a readable handle pointer. The handle must satisfy
/// the query's layout contract and, on success, the retail setter's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_handle_result_replace_value(wrapper: *const *mut u32, value: u32) {
    let mut first = 0;
    let mut second = 0;
    if opaque_handle_result_query(wrapper.read(), &mut first, &mut second) == 0 {
        second = value;
        #[cfg(target_os = "none")]
        let set: HandleResultSet = core::mem::transmute(0x082e8534usize);
        #[cfg(not(target_os = "none"))]
        let set = core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_HANDLE_RESULT_SET));
        set(wrapper.read(), first, &second);
    }
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

#[cfg(test)]
mod replace_tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    // Behavioral model of the setter's observable validation/state update.
    // Notification is firmware-owned and is not executed by host tests.
    unsafe extern "C" fn set_result(handle: *mut u32, mode: u32, value: *const u32) -> u32 {
        let status = crate::mode_position_validate::mode_position_validate(mode, value.cast());
        if status != 0 { return status; }
        handle.add(FIRST_RESULT_WORD).write(mode);
        handle.add(0x200 / 4).write(handle.add(0x200 / 4).read() | 3);
        handle.add(SECOND_RESULT_WORD).write(value.read());
        0
    }

    #[test]
    fn query_rejection_leaves_state_untouched_and_never_sets() {
        let _lock = LOCK.lock();
        unsafe { OPAQUE_HANDLE_RESULT_SET = missing_handle_result_set; }
        let mut handle = [0u32; SECOND_RESULT_WORD + 1];
        for (magic, count) in [(0, 1), (RHTP_HANDLE_MAGIC, 0), (RHTP_HANDLE_MAGIC, u32::MAX)] {
            handle[0] = magic;
            handle[RESULT_COUNT_WORD] = count;
            let before = handle;
            let wrapper = handle.as_mut_ptr();
            unsafe { opaque_handle_result_replace_value(&wrapper, 12); }
            assert_eq!(handle, before);
        }
        let wrapper = core::ptr::null_mut();
        unsafe { opaque_handle_result_replace_value(&wrapper, 12); }
    }

    #[test]
    fn replacement_preserves_mode_and_obeys_setter_boundaries() {
        let _lock = LOCK.lock();
        unsafe { OPAQUE_HANDLE_RESULT_SET = set_result; }
        for mode in [0, 1, 2, 3, u32::MAX] {
            for value in [i32::MIN, -63, -62, 0, 12, 63, 64, i32::MAX] {
                let mut handle = [0u32; SECOND_RESULT_WORD + 1];
                handle[0] = RHTP_HANDLE_MAGIC;
                handle[RESULT_COUNT_WORD] = 1;
                handle[FIRST_RESULT_WORD] = mode;
                handle[SECOND_RESULT_WORD] = 42;
                handle[0x200 / 4] = 0x80;
                let mut expected = handle;
                if mode == 2 && (-62..=63).contains(&value) {
                    expected[SECOND_RESULT_WORD] = value as u32;
                    expected[0x200 / 4] = 0x83;
                }
                let wrapper = handle.as_mut_ptr();
                unsafe { opaque_handle_result_replace_value(&wrapper, value as u32); }
                assert_eq!(handle, expected, "mode {mode}, value {value}");
            }
        }
        unsafe { OPAQUE_HANDLE_RESULT_SET = missing_handle_result_set; }
    }
}

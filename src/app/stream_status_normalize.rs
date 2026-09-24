//! Normalizes a stream operation's status code.
//!
//! `stream_status_normalize` — original: `FUN_080dac58` @ `0x080dac58`
//! (80 bytes, `0x080dac58..0x080daca7`; the next independent frame begins
//! with `push {r4-r7}` at `0x080daca8`). A full raw-image A32 branch decode
//! finds three incoming plain `bl` calls (0x0808e50c, 0x080c6cb8, and
//! 0x081031d4), no predicated incoming calls, and one plain body `bl` to
//! unported `FUN_0814852c` at `0x0814852c`.
//!
//! # Algorithm
//!
//! Status selectors 1, 4, and 5 always normalize to 1; selector 3 normalizes
//! to 3. All other selectors use `FUN_0814852c`'s opaque status result. When
//! the first input is zero and the other two inputs are also zero, a queried
//! result of 1 instead normalizes to 2. Deliberate deviation: the unported
//! callee has no recovered identity, so ARM builds call its verified retail
//! address and host builds inject an ABI-compatible seam.

type RetailStatusQuery = unsafe extern "C" fn() -> u32;

const RETAIL_STATUS_QUERY_ADDRESS: usize = 0x0814_852c;

#[cfg(target_os = "none")]
unsafe fn retail_status_query() -> u32 {
    let query = unsafe { core::mem::transmute::<usize, RetailStatusQuery>(RETAIL_STATUS_QUERY_ADDRESS) };
    unsafe { query() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_status_query() -> u32 {
    panic!("stream_status_normalize requires retail status query 0x0814852c")
}

#[cfg(not(target_os = "none"))]
pub static mut STREAM_STATUS_QUERY: RetailStatusQuery = missing_status_query;

/// Normalizes the opaque stream status selector and fallback query result.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_status_normalize(first: u32, second: u32, third: u32, selector: u32) -> u32 {
    if selector == 4 || selector == 5 || selector == 1 {
        return 1;
    }
    if selector == 3 {
        return 3;
    }

    #[cfg(target_os = "none")]
    let result = unsafe { retail_status_query() };
    #[cfg(not(target_os = "none"))]
    let result = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_STATUS_QUERY))() };

    if first == 0 && second == 0 && third == 0 && result == 1 {
        2
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut QUERY_RESULT: u32 = 0;
    static mut QUERY_CALLS: u32 = 0;

    unsafe extern "C" fn query_fixture() -> u32 {
        QUERY_CALLS += 1;
        QUERY_RESULT
    }

    unsafe fn install_query(result: u32) {
        STREAM_STATUS_QUERY = query_fixture;
        QUERY_RESULT = result;
        QUERY_CALLS = 0;
    }

    #[test]
    fn fixed_selectors_bypass_the_status_query() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            install_query(9);
            assert_eq!(stream_status_normalize(7, 8, 9, 1), 1);
            assert_eq!(stream_status_normalize(7, 8, 9, 4), 1);
            assert_eq!(stream_status_normalize(7, 8, 9, 5), 1);
            assert_eq!(stream_status_normalize(7, 8, 9, 3), 3);
            assert_eq!(QUERY_CALLS, 0);
        }
    }

    #[test]
    fn fallback_query_only_remaps_the_all_zero_inputs_case() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            install_query(1);
            assert_eq!(stream_status_normalize(0, 0, 0, 0), 2);
            assert_eq!(stream_status_normalize(1, 0, 0, 0), 1);
            assert_eq!(stream_status_normalize(0, 1, 0, 0), 1);
            assert_eq!(stream_status_normalize(0, 0, 1, 0), 1);
            assert_eq!(QUERY_CALLS, 4);

            install_query(8);
            assert_eq!(stream_status_normalize(0, 0, 0, 2), 8);
            assert_eq!(QUERY_CALLS, 1);
        }
    }
}

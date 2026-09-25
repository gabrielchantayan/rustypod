//! Stream current-position conversion.
//!
//! `stream_current_position_milliseconds` — original: `FUN_08038fc0` @
//! `0x08038fc0` (24 bytes; true extent `0x08038fc0..0x08038fd8`; the next
//! independent frame begins at `0x08038fdc`). A whole-image A32 branch decode
//! finds three inbound plain `bl` calls and no predicated `bl` callers. The
//! body has one plain `bl` to unported `FUN_08038f60` @ `0x08038f60`, then a
//! tail `b` to unported `FUN_08038ebc` @ `0x08038ebc`.
//!
//! Algorithm: query the stream's opaque current-position counter, then
//! tail-dispatch its conversion to milliseconds. Deliberate deviation: neither
//! callee has a recovered identity, so ARM builds call their verified retail
//! addresses and host builds inject ABI-compatible seams. The ARM tail branch
//! is represented by a normal Rust return.

type RetailCurrentPositionQuery = unsafe extern "C" fn(*mut u8) -> u32;
type RetailPositionToMilliseconds = unsafe extern "C" fn(*mut u8, u32) -> u32;

const RETAIL_CURRENT_POSITION_QUERY_ADDRESS: usize = 0x0803_8f60;
const RETAIL_POSITION_TO_MILLISECONDS_ADDRESS: usize = 0x0803_8ebc;

#[cfg(target_os = "none")]
unsafe fn retail_current_position_query(stream: *mut u8) -> u32 {
    let query = unsafe {
        core::mem::transmute::<usize, RetailCurrentPositionQuery>(RETAIL_CURRENT_POSITION_QUERY_ADDRESS)
    };
    unsafe { query(stream) }
}

#[cfg(target_os = "none")]
unsafe fn retail_position_to_milliseconds(stream: *mut u8, position: u32) -> u32 {
    let convert = unsafe {
        core::mem::transmute::<usize, RetailPositionToMilliseconds>(RETAIL_POSITION_TO_MILLISECONDS_ADDRESS)
    };
    unsafe { convert(stream, position) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_current_position_query(_stream: *mut u8) -> u32 {
    panic!("stream_current_position_milliseconds requires retail query 0x08038f60")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_position_to_milliseconds(_stream: *mut u8, _position: u32) -> u32 {
    panic!("stream_current_position_milliseconds requires retail converter 0x08038ebc")
}

#[cfg(not(target_os = "none"))]
pub static mut STREAM_CURRENT_POSITION_QUERY: RetailCurrentPositionQuery = missing_current_position_query;
#[cfg(not(target_os = "none"))]
pub static mut STREAM_POSITION_TO_MILLISECONDS: RetailPositionToMilliseconds = missing_position_to_milliseconds;

/// Returns the current opaque stream position converted to milliseconds.
///
/// # Safety
/// `stream` must be valid for both retail callees' unchecked object layouts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_current_position_milliseconds(stream: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let position = unsafe { retail_current_position_query(stream) };
    #[cfg(not(target_os = "none"))]
    let position = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_CURRENT_POSITION_QUERY))(stream) };

    #[cfg(target_os = "none")]
    return unsafe { retail_position_to_milliseconds(stream, position) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_POSITION_TO_MILLISECONDS))(stream, position) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut QUERY_STREAM: usize = 0;
    static mut CONVERT_STREAM: usize = 0;
    static mut CONVERT_POSITION: u32 = 0;
    static mut QUERY_RESULT: u32 = 0;
    static mut CONVERT_RESULT: u32 = 0;

    unsafe extern "C" fn query_fixture(stream: *mut u8) -> u32 {
        QUERY_STREAM = stream as usize;
        QUERY_RESULT
    }

    unsafe extern "C" fn convert_fixture(stream: *mut u8, position: u32) -> u32 {
        CONVERT_STREAM = stream as usize;
        CONVERT_POSITION = position;
        CONVERT_RESULT
    }

    unsafe fn install_seams(position: u32, milliseconds: u32) {
        STREAM_CURRENT_POSITION_QUERY = query_fixture;
        STREAM_POSITION_TO_MILLISECONDS = convert_fixture;
        QUERY_STREAM = 0;
        CONVERT_STREAM = 0;
        CONVERT_POSITION = 0;
        QUERY_RESULT = position;
        CONVERT_RESULT = milliseconds;
    }

    #[test]
    fn forwards_the_opaque_position_and_stream_to_the_converter() {
        let _lock = TEST_LOCK.lock();
        let mut stream = [0u8; 1];
        unsafe {
            install_seams(0xffff_fffe, 0x1234_5678);
            assert_eq!(stream_current_position_milliseconds(stream.as_mut_ptr()), 0x1234_5678);
            assert_eq!(QUERY_STREAM, stream.as_mut_ptr() as usize);
            assert_eq!(CONVERT_STREAM, stream.as_mut_ptr() as usize);
            assert_eq!(CONVERT_POSITION, 0xffff_fffe);
        }
    }

    #[test]
    fn forwards_zero_position_without_special_casing() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            install_seams(0, 0);
            assert_eq!(stream_current_position_milliseconds(core::ptr::null_mut()), 0);
            assert_eq!(QUERY_STREAM, 0);
            assert_eq!(CONVERT_STREAM, 0);
            assert_eq!(CONVERT_POSITION, 0);
        }
    }
}

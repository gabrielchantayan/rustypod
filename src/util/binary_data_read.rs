//! `binary_data_read` — original: `FUN_0809c634` @ `0x0809c634`.
//!
//! Raw `osos.dec` words establish the 160-byte extent
//! `0x0809c634..0x0809c6d4`; the following bytes are the error string and the
//! next real function starts at `0x0809c6fc`. It has five branch-with-link
//! instructions: two plain `bl`, three indirect `blx`, and no predicated
//! forms.
//!
//! Calls the parser's skip callback, requires a digit at its cursor, reads a
//! binary value through its value callback, consumes it, then advances the
//! cursor past its delimiter and value. On failure it reports the stock error,
//! latches status three, and returns zero.
//!
//! Deliberate deviation: host builds use callback seams and an ASCII digit
//! predicate because target-width callback pointers and the installed retail
//! LC_CTYPE table are not host-mapped. Target builds call the exact callbacks,
//! `isdigit` at `0x082d731c`, and error reporter at `0x0804d17c`.

const CURSOR: usize = 0;
const END: usize = 2;
const ERROR_STATUS: usize = 3;
const SKIP_CALLBACK: usize = 7;
const CONSUME_CALLBACK: usize = 8;
const READ_VALUE_CALLBACK: usize = 9;
const INVALID_SIZE: &[u8] = b"read_binary_data: invalid size field\n\0";

type ParserCallback = unsafe extern "C" fn(*mut u32);
type ReadValueCallback = unsafe extern "C" fn(*mut u32) -> u32;
type ErrorReporter = unsafe extern "C" fn(*const u8);
#[cfg(target_arch = "arm")]
static mut RETAIL_ISDIGIT: unsafe extern "C" fn(i32) -> i32 = crate::runtime::ctype::isdigit;


#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn skip(parser: *mut u32) {
    let callback: ParserCallback = unsafe { core::mem::transmute(parser.add(SKIP_CALLBACK).read()) };
    unsafe { callback(parser) };
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn consume(parser: *mut u32) {
    let callback: ParserCallback = unsafe { core::mem::transmute(parser.add(CONSUME_CALLBACK).read()) };
    unsafe { callback(parser) };
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn read_value(parser: *mut u32) -> u32 {
    let callback: ReadValueCallback = unsafe { core::mem::transmute(parser.add(READ_VALUE_CALLBACK).read()) };
    unsafe { callback(parser) }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn report_invalid_size() {
    let report: ErrorReporter = unsafe { core::mem::transmute(0x0804_d17cusize) };
    unsafe { report(INVALID_SIZE.as_ptr()) };
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_parser_callback(_: *mut u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_read_value(_: *mut u32) -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_error_reporter(_: *const u8) {}

/// Host replacements for the three target parser callbacks and error reporter.
#[cfg(not(target_arch = "arm"))]
pub static mut BINARY_DATA_READ_SKIP: ParserCallback = missing_parser_callback;
#[cfg(not(target_arch = "arm"))]
pub static mut BINARY_DATA_READ_CONSUME: ParserCallback = missing_parser_callback;
#[cfg(not(target_arch = "arm"))]
pub static mut BINARY_DATA_READ_VALUE: ReadValueCallback = missing_read_value;
#[cfg(not(target_arch = "arm"))]
pub static mut BINARY_DATA_READ_ERROR: ErrorReporter = missing_error_reporter;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn skip(parser: *mut u32) { unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BINARY_DATA_READ_SKIP))(parser) } }
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn consume(parser: *mut u32) { unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BINARY_DATA_READ_CONSUME))(parser) } }
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn read_value(parser: *mut u32) -> u32 { unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BINARY_DATA_READ_VALUE))(parser) } }
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn report_invalid_size() { unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BINARY_DATA_READ_ERROR))(INVALID_SIZE.as_ptr()) } }

/// Reads a digit-prefixed binary value from `parser`, storing its value and
/// first payload byte in `value` and `payload_start` respectively.
///
/// # Safety
///
/// `parser` must point to at least ten target-layout `u32` fields. Its cursor
/// and end fields must delimit readable input; its callback fields must be
/// valid on target builds.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn binary_data_read(parser: *mut u32, value: *mut u32, payload_start: *mut u32) -> u32 {
    unsafe { skip(parser) };
    let cursor = unsafe { parser.add(CURSOR).read() };
    let end = unsafe { parser.add(END).read() };
    let is_digit = if cursor < end {
        #[cfg(target_arch = "arm")]
        { unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_ISDIGIT))((cursor as *const u8).read() as i32) != 0 } }
        #[cfg(not(target_arch = "arm"))]
        { unsafe { (cursor as *const u8).read().is_ascii_digit() } }
    } else { false };
    if !is_digit {
        unsafe { report_invalid_size() };
        unsafe { parser.add(ERROR_STATUS).write(3) };
        return 0;
    }
    let parsed_value = unsafe { read_value(parser) };
    unsafe { value.write(parsed_value) };
    unsafe { consume(parser) };
    let delimiter = unsafe { parser.add(CURSOR).read() };
    unsafe { payload_start.write(delimiter.wrapping_add(1)) };
    unsafe { parser.add(CURSOR).write(delimiter.wrapping_add(parsed_value).wrapping_add(1)) };
    if unsafe { parser.add(ERROR_STATUS).read() } == 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicU32, Ordering};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::BINARY_DATA_READ, FIXTURE_LEN).map(|pointer| pointer as usize));
    static LOCK: Mutex<()> = Mutex::new(());
    static VALUE: AtomicU32 = AtomicU32::new(0);
    static SKIPS: AtomicU32 = AtomicU32::new(0);
    static CONSUMES: AtomicU32 = AtomicU32::new(0);
    static ERRORS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn record_skip(_: *mut u32) { SKIPS.fetch_add(1, Ordering::SeqCst); }
    unsafe extern "C" fn record_consume(_: *mut u32) { CONSUMES.fetch_add(1, Ordering::SeqCst); }
    unsafe extern "C" fn record_value(_: *mut u32) -> u32 { VALUE.load(Ordering::SeqCst) }
    unsafe extern "C" fn record_error(_: *const u8) { ERRORS.fetch_add(1, Ordering::SeqCst); }

    struct SeamReset { skip: ParserCallback, consume: ParserCallback, value: ReadValueCallback, error: ErrorReporter }
    impl Drop for SeamReset { fn drop(&mut self) { unsafe { BINARY_DATA_READ_SKIP = self.skip; BINARY_DATA_READ_CONSUME = self.consume; BINARY_DATA_READ_VALUE = self.value; BINARY_DATA_READ_ERROR = self.error; } } }
    fn install(value: u32) -> SeamReset {
        VALUE.store(value, Ordering::SeqCst); SKIPS.store(0, Ordering::SeqCst); CONSUMES.store(0, Ordering::SeqCst); ERRORS.store(0, Ordering::SeqCst);
        let reset = unsafe { SeamReset { skip: BINARY_DATA_READ_SKIP, consume: BINARY_DATA_READ_CONSUME, value: BINARY_DATA_READ_VALUE, error: BINARY_DATA_READ_ERROR } };
        unsafe { BINARY_DATA_READ_SKIP = record_skip; BINARY_DATA_READ_CONSUME = record_consume; BINARY_DATA_READ_VALUE = record_value; BINARY_DATA_READ_ERROR = record_error; }
        reset
    }

    #[test]
    fn digit_prefix_reads_value_and_advances_past_payload() {
        let _guard = LOCK.lock(); let Some(base) = *FIXTURE else { assert!(note_missing_u32_fixture("util/binary_data_read")); return; };
        let _reset = install(4); unsafe { (base as *mut u8).write_bytes(0, FIXTURE_LEN); (base as *mut u8).write(b'7'); }
        let mut parser = [base as u32, 0, (base + 1) as u32, 0, 0, 0, 0, 0, 0, 0]; let mut value = 0; let mut payload_start = 0;
        assert_eq!(unsafe { binary_data_read(parser.as_mut_ptr(), &mut value, &mut payload_start) }, 1);
        assert_eq!((value, payload_start, parser[0]), (4, base as u32 + 1, base as u32 + 5)); assert_eq!((SKIPS.load(Ordering::SeqCst), CONSUMES.load(Ordering::SeqCst), ERRORS.load(Ordering::SeqCst)), (1, 1, 0));
    }

    #[test]
    fn empty_or_nondigit_input_reports_and_latches_status() {
        let _guard = LOCK.lock(); let Some(base) = *FIXTURE else { assert!(note_missing_u32_fixture("util/binary_data_read")); return; };
        let _reset = install(9); unsafe { (base as *mut u8).write(b'x'); }
        for end in [base as u32, base as u32 + 1] {
            let mut parser = [base as u32, 0, end, 0, 0, 0, 0, 0, 0, 0]; let mut value = 0xfeed_beef; let mut payload_start = 0xdead_beef;
            assert_eq!(unsafe { binary_data_read(parser.as_mut_ptr(), &mut value, &mut payload_start) }, 0);
            assert_eq!((parser[3], value, payload_start), (3, 0xfeed_beef, 0xdead_beef));
        }
        assert_eq!((SKIPS.load(Ordering::SeqCst), CONSUMES.load(Ordering::SeqCst), ERRORS.load(Ordering::SeqCst)), (2, 0, 2));
    }
}

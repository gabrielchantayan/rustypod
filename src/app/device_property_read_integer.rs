//! `device_property_read_integer` — original: `FUN_080a7444` @ `0x080a7444`
//! (56 bytes, `0x080a7444..0x080a747c`).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM words establish two outbound plain `bl` calls (`0x080962f0` and
//! `0x0802f92c`) and no predicated outbound `bl` calls. Four inbound direct
//! plain `bl` sites (`0x081d3d78`, `0x081d3f98`, `0x081d56b0`, and
//! `0x081d5890`) reach this entry; no predicated inbound calls were found.
//! It seeds a 14-byte text buffer with its four incoming argument words, asks
//! the unrecovered reader to fill it, then scans that text with the retail
//! format at `0x083e8ba4` into `value`. Its success result is the reader's
//! result; the scan result is deliberately ignored.
//!
//! # Deliberate deviations
//!
//! The reader at `0x080962f0` has no recovered semantic identity in
//! `names.yaml`; target builds call its verified retailOS address and host
//! builds use a narrow callback seam. Rust returns normally after the scan
//! rather than reproducing the original stack frame and register saves.

/// ABI of the unported text reader at `0x080962f0`.
pub type DevicePropertyReadText = unsafe extern "C" fn(*mut u8, *mut u8, u32) -> u32;
/// ABI of the retail `sscanf` call at `0x0802f92c` for this one output argument.
pub type ScanInteger = unsafe extern "C" fn(*const u8, *const u8, *mut i32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_device_property_read_text(_property: *mut u8, _text: *mut u8, _capacity: u32) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_scan_integer(_text: *const u8, _format: *const u8, _value: *mut i32) -> i32 {
    0
}

/// Host seams for the two retailOS calls.
#[cfg(not(target_os = "none"))]
pub static mut DEVICE_PROPERTY_READ_TEXT: DevicePropertyReadText = missing_device_property_read_text;
#[cfg(not(target_os = "none"))]
pub static mut SCAN_INTEGER: ScanInteger = missing_scan_integer;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn device_property_read_text_target() -> DevicePropertyReadText {
    core::mem::transmute(0x0809_62f0usize)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn scan_integer_target() -> ScanInteger {
    core::mem::transmute(0x0802_f92cusize)
}

/// Reads a device property's text representation and scans its integer value.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn device_property_read_integer(
    property: *mut u8,
    value: *mut i32,
    seed2: u32,
    seed3: u32,
) -> u32 {
    let mut text = [0u8; 16];
    let seeds = [property as u32, value as u32, seed2, seed3];
    for (index, seed) in seeds.iter().enumerate() {
        unsafe { (text.as_mut_ptr().cast::<u32>().add(index)).write(*seed) };
    }

    #[cfg(target_os = "none")]
    let read = unsafe { device_property_read_text_target()(property, text.as_mut_ptr(), 14) };
    #[cfg(not(target_os = "none"))]
    let read = unsafe { DEVICE_PROPERTY_READ_TEXT(property, text.as_mut_ptr(), 14) };

    if read == 0 {
        return 0;
    }

    #[cfg(target_os = "none")]
    unsafe { scan_integer_target()(text.as_ptr(), 0x083e_8ba4usize as *const u8, value) };
    #[cfg(not(target_os = "none"))]
    unsafe { SCAN_INTEGER(text.as_ptr(), 0x083e_8ba4usize as *const u8, value) };
    1
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut READ_RESULT: u32 = 0;
    static mut READ_CAPACITY: u32 = 0;
    static mut SCAN_CALLS: u32 = 0;
    static mut SCAN_VALUE: i32 = 0;

    unsafe extern "C" fn record_read(_property: *mut u8, text: *mut u8, capacity: u32) -> u32 {
        unsafe {
            READ_CAPACITY = capacity;
            text.write(b'4');
            text.add(1).write(0);
            READ_RESULT
        }
    }

    unsafe extern "C" fn record_scan(text: *const u8, format: *const u8, value: *mut i32) -> i32 {
        unsafe {
            assert_eq!(*text, b'4');
            assert_eq!(format as usize, 0x083e_8ba4);
            SCAN_CALLS += 1;
            value.write(SCAN_VALUE);
        }
        1
    }

    #[test]
    fn successful_read_scans_even_when_the_scan_result_is_ignored() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            READ_RESULT = 1;
            READ_CAPACITY = 0;
            SCAN_CALLS = 0;
            SCAN_VALUE = 42;
            DEVICE_PROPERTY_READ_TEXT = record_read;
            SCAN_INTEGER = record_scan;
        }
        let mut property = 0u8;
        let mut value = 0;
        assert_eq!(unsafe { device_property_read_integer(&mut property, &mut value, 0, 0) }, 1);
        unsafe {
            assert_eq!(READ_CAPACITY, 14);
            assert_eq!(SCAN_CALLS, 1);
        }
        assert_eq!(value, 42);
    }

    #[test]
    fn failed_read_does_not_scan_or_modify_the_value() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            READ_RESULT = 0;
            SCAN_CALLS = 0;
            DEVICE_PROPERTY_READ_TEXT = record_read;
            SCAN_INTEGER = record_scan;
        }
        let mut property = 0u8;
        let mut value = -7;
        assert_eq!(unsafe { device_property_read_integer(&mut property, &mut value, 1, 2) }, 0);
        unsafe { assert_eq!(SCAN_CALLS, 0) };
        assert_eq!(value, -7);
    }
}

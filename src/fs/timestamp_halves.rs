//! Splits the current packed calendar timestamp: `FUN_082e2264` at
//! **0x082e2264**.
//!
//! # Raw extent and call sites
//!
//! Raw ARM confirms the 32-byte extent `0x082e2264..0x082e2284`; the next
//! separately entered function begins at `0x082e2284`. Decoding every ARM
//! branch word finds two direct call sites (`0x082e32a4`, `0x082e48fc`), both
//! unconditional `bl`; there are no predicated calls or tail branches.
//!
//! # Algorithm
//!
//! The routine obtains a packed 32-bit calendar timestamp from `0x08051d1c`,
//! writes its upper halfword to `output[0]` and lower halfword to `output[1]`,
//! then returns `output`.
//!
//! Deliberate deviation: the opaque packed-calendar source at `0x08051d1c`
//! remains a verified retailOS target call. Host builds expose that boundary as
//! a replaceable operation rather than assigning an unverified identity.

/// Opaque retailOS packed-calendar timestamp source at `0x08051d1c`.
type PackedCalendarTimestamp = unsafe extern "C" fn() -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn packed_calendar_timestamp() -> u32 {
    let source: PackedCalendarTimestamp = core::mem::transmute(0x0805_1d1cusize);
    source()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_packed_calendar_timestamp() -> u32 {
    panic!("timestamp_halves called without a host seam")
}

#[cfg(not(target_os = "none"))]
static mut PACKED_CALENDAR_TIMESTAMP: PackedCalendarTimestamp = unavailable_packed_calendar_timestamp;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn packed_calendar_timestamp() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(PACKED_CALENDAR_TIMESTAMP))()
}

/// Splits the current packed calendar timestamp into upper then lower halves.
///
/// # Safety
///
/// `output` must point to two writable, aligned halfwords. RetailOS supplies
/// this precondition; the port deliberately adds no null check.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timestamp_halves(output: *mut u16) -> *mut u16 {
    let timestamp = packed_calendar_timestamp();
    output.write((timestamp >> 16) as u16);
    output.add(1).write(timestamp as u16);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut TIMESTAMP: u32 = 0;

    unsafe extern "C" fn recorded_packed_calendar_timestamp() -> u32 {
        TIMESTAMP
    }

    struct SourceReset(PackedCalendarTimestamp);

    impl Drop for SourceReset {
        fn drop(&mut self) {
            unsafe {
                PACKED_CALENDAR_TIMESTAMP = self.0;
            }
        }
    }

    #[test]
    fn splits_zero_and_all_set_timestamp_words() {
        let _lock = TEST_LOCK.lock();
        let reset = unsafe {
            let prior = core::ptr::read_volatile(core::ptr::addr_of!(PACKED_CALENDAR_TIMESTAMP));
            PACKED_CALENDAR_TIMESTAMP = recorded_packed_calendar_timestamp;
            SourceReset(prior)
        };

        for (timestamp, expected) in [(0, [0, 0]), (0xffff_ffff, [0xffff, 0xffff]), (0x1122_3344, [0x1122, 0x3344])] {
            let mut output = [0xdead_u16; 2];
            unsafe {
                TIMESTAMP = timestamp;
                assert_eq!(timestamp_halves(output.as_mut_ptr()), output.as_mut_ptr());
            }
            assert_eq!(output, expected);
        }

        drop(reset);
    }
}

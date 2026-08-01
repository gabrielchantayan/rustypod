//! RTC time read: fetch the PCF50635 real-time-clock registers over the
//! PMU I2C bus and convert the 7-byte BCD block into a
//! (days, seconds-of-day) pair — the device's wall clock.
//!
//! Original: `FUN_08056150` @ 0x08056150 (72 bytes; 1 call site, `bl` @
//! 0x0806e400 inside `FUN_0806e3dc`, the 64-bit system-time builder that
//! scales the day count by 0x80*675 = 86400 and folds the seconds in).
//!
//! Algorithm (mirrored from the disassembly):
//! 1. `stmdb sp!, {r0..r3, r4, r5, r6, lr}` spills the argument
//!    registers into the frame; the saved r2/r3 slots double as the
//!    8-byte RTC buffer (so the third/fourth argument words SEED the
//!    buffer — visible when the read fails partway) and the saved r0/r1
//!    slots double as the (days, seconds) out-pair.
//! 2. `FUN_082e58f0(0, buf)` — mutexed I2C read of the RTC: slave 0x73
//!    (the PCF50635 PMU), register block 0x59, 7 bytes (sec, min, hour,
//!    weekday, day, month, year; FUN_0836d698).
//! 3. `FUN_0809e3e8(out_pair, buf)` converts BCD to a day count and a
//!    seconds-of-day count. BCD decode (FUN_080ed424) is
//!    `v - 6*(v>>4)` for `v < 0x9a`, else 99. The day count is the
//!    Hinnant civil-to-days formula over the 2-digit year:
//!    `adj = (14 - month) / 12` (UNSIGNED divide @ 0x08036f14 — a month
//!    above 14 wraps to a huge quotient), `y = year - adj + 0x1a90`,
//!    `mp = month + 12*adj - 3`,
//!    `days = 365*y + day + (153*mp + 2)/5 + y/4 - y/100 + y/400
//!    - 0x7d2d` (365 from the literal @ 0x0809e4cc, 0x7d2d = 32045; the
//!    /5, /100, /400 are signed truncating __rt_sdiv @ 0x08031568, the
//!    /4 is the compiler's add-3-and-asr truncating idiom). The year is
//!    biased by 0x1a90 = 6800, a multiple of 400, so the 2-digit year's
//!    leap pattern is undisturbed. Seconds-of-day is
//!    `hour*0xe10 + min*60 + sec` from buf[2]/buf[1]/buf[0].
//! 4. The out-pair is stored to *days_out / *secs_out even when the I2C
//!    read failed (the conversion runs unconditionally); the return is
//!    0 on success or -5 (`mvnne r0, #4`) on read error.
//!
//! The mutexed wrapper FUN_082e58f0 is ported as
//! [`crate::drivers::i2c::pmu_i2c_read_regs`] and is the shipped
//! default of the [`RTC_READ_REGS`] dispatch slot below. The hardware
//! chain under it (FUN_0836d698 -> FUN_0836d3b8 -> FUN_0836bb84 /
//! FUN_0836b950, the S5L8702 I2C transfer to slave 0x73) stays
//! unported behind i2c.rs's `PMU_READ_REGS` slot, whose default stub
//! fails closed with the driver's own bad-bank code 9 — so the wired
//! defaults still make [`rtc_read_time`] report -5 and convert
//! whatever the seeds left in the buffer. The BCD conversion
//! FUN_0809e3e8 is pure arithmetic and is ported as
//! [`super::civil::bcd_datetime_to_days_secs`] (on the ported
//! __rt_udiv/__rt_sdiv); all adds/multiplies wrap to match ARM
//! flag-less arithmetic.

/// The mutexed RTC register read behind [`rtc_read_time`]: stock
/// `FUN_082e58f0` @ 0x082e58f0. `bank` 0 selects the time registers
/// (0x59), bank 1 the alarm registers (0x60); returns 0 on success.
pub type RtcReadFn = unsafe extern "C" fn(bank: u32, buf: *mut u8) -> i32;

/// The opaque owner passed to [`rtc_context_handle`]. On the target, the
/// nested RTC context pointer is the 32-bit word at +0xf00. A native host
/// pointer widens the tail only; the target-relevant offset stays exact.
#[repr(C)]
pub struct RtcContextOwner {
    reserved: [u8; 0xf00],
    rtc_context: *const RtcContext,
}

/// The portion of the nested RTC context reached by the stock accessor.
#[repr(C)]
pub struct RtcContext {
    reserved: [u8; 0x0c],
    handle: u32,
}

const _: [u8; 0xf00] = [0; core::mem::offset_of!(RtcContextOwner, rtc_context)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RtcContext, handle)];
const _: [u8; 0x10] = [0; core::mem::size_of::<RtcContext>()];

/// rtc_context_handle — original: `FUN_08056124` @ 0x08056124 (12 bytes).
///
/// Follow the RTC owner's context pointer at +0xf00 and return that nested
/// context's opaque handle word at +0x0c. The raw ARM body is two `ldr`
/// instructions followed by `bx lr`: r0 is both the owner argument and the
/// returned 32-bit handle. The sole recovered caller caches this handle at
/// its +0x54 before it dispatches the nested context's companion +0xb54
/// word. Deviation: none.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rtc_context_handle(owner: *const RtcContextOwner) -> u32 {
    unsafe { (*(*owner).rtc_context).handle }
}

/// rtc_static_time_pair — original: `FUN_08056130` @ 0x08056130 (28 bytes).
///
/// Copy the firmware's read-only fallback `(day_count, seconds_of_day)` pair
/// into the two ARM ABI output pointers, in that order, and return zero. The
/// body loads the adjacent source words at `0x089caa98` then writes the first
/// through r0 and the second through r1; callers use the same order when
/// comparing or constructing a 64-bit system time. The source's retained
/// retail image contents are `0x7461_4400, 0x6d69_5465`. Deviation: none.
static RTC_STATIC_TIME_PAIR: [u32; 2] = [0x7461_4400, 0x6d69_5465];

#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rtc_static_time_pair(
    days_out: *mut u32,
    secs_out: *mut u32,
) -> i32 {
    unsafe {
        *days_out = core::ptr::read_volatile(RTC_STATIC_TIME_PAIR.as_ptr());
        *secs_out = core::ptr::read_volatile(RTC_STATIC_TIME_PAIR.as_ptr().add(1));
    }
    0
}

/// Pre-port default slot, kept for host tests: fail closed with
/// FUN_0836d698's own bad-bank code 9. The shipped default is now the
/// ported [`crate::drivers::i2c::pmu_i2c_read_regs`], which fails
/// closed identically through its `PMU_READ_REGS` stub.
unsafe extern "C" fn rtc_read_stub(_bank: u32, _buf: *mut u8) -> i32 {
    9
}

/// The active RTC register read: the ported mutexed I2C entry
/// (drivers/i2c.rs). Host tests install a recording mock.
pub static mut RTC_READ_REGS: RtcReadFn = crate::drivers::i2c::pmu_i2c_read_regs;

/// rtc_read_time @ 0x08056150 — read the RTC and return the wall clock
/// as a day count and a seconds-of-day count. 0 on success, -5 when the
/// I2C read reports an error; the outputs are written either way. The
/// seed words reproduce the original's saved-r2/r3 buffer slots.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rtc_read_time(
    days_out: *mut u32,
    secs_out: *mut u32,
    seed_lo: u32,
    seed_hi: u32,
) -> i32 {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&seed_lo.to_le_bytes());
    buf[4..].copy_from_slice(&seed_hi.to_le_bytes());
    let read = core::ptr::read_volatile(core::ptr::addr_of!(RTC_READ_REGS));
    let status = read(0, buf.as_mut_ptr());
    let mut pair = [0i32; 2];
    super::civil::bcd_datetime_to_days_secs(pair.as_mut_ptr(), buf.as_ptr());
    *days_out = pair[0] as u32;
    *secs_out = pair[1] as u32;
    if status != 0 {
        -5
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::time::civil::{bcd_datetime_to_days_secs, bcd_to_bin};
    use std::sync::{Mutex, MutexGuard};

    /// The ported FUN_0809e3e8 through its raw-pointer ABI, returning
    /// the (days, seconds) pair.
    fn convert(buf: &[u8; 8]) -> (u32, u32) {
        let mut pair = [0i32; 2];
        unsafe { bcd_datetime_to_days_secs(pair.as_mut_ptr(), buf.as_ptr()) };
        (pair[0] as u32, pair[1] as u32)
    }

    /// Serializes tests that swap the dispatch slot.
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    static mut MOCK_REGS: [u8; 7] = [0; 7];
    static mut MOCK_STATUS: i32 = 0;
    static mut MOCK_CALLS: u32 = 0;
    static mut MOCK_LAST_BANK: u32 = 0xffffffff;

    unsafe extern "C" fn mock_rtc_read(bank: u32, buf: *mut u8) -> i32 {
        MOCK_CALLS += 1;
        MOCK_LAST_BANK = bank;
        if MOCK_STATUS == 0 {
            core::ptr::copy_nonoverlapping(MOCK_REGS.as_ptr(), buf, 7);
        }
        MOCK_STATUS
    }

    fn install_mock(regs: [u8; 7], status: i32) -> MutexGuard<'static, ()> {
        let guard = SLOT_LOCK.lock().unwrap();
        unsafe {
            MOCK_REGS = regs;
            MOCK_STATUS = status;
            MOCK_CALLS = 0;
            MOCK_LAST_BANK = 0xffffffff;
            RTC_READ_REGS = mock_rtc_read;
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            RTC_READ_REGS = crate::drivers::i2c::pmu_i2c_read_regs;
        }
        drop(guard);
    }

    /// Naive proleptic-Gregorian day counter over the 2-digit RTC year,
    /// days since 0000-03-01 (the Hinnant epoch), computed by loops.
    fn is_leap(y: i32) -> bool {
        y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
    }

    fn ref_days_since_mar1_year0(y: i32, m: i32, d: i32) -> i32 {
        let yy = if m <= 2 { y - 1 } else { y };
        let mp = if m <= 2 { m + 9 } else { m - 3 };
        // Month lengths from March. February is the LAST month of the
        // March-year, so no in-year leap bump is needed; instead each
        // full March-year k is 366 days when year k+1 is leap.
        const MLEN: [i32; 12] = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 28];
        let mut days = d - 1;
        for len in MLEN.iter().take(mp as usize) {
            days += len;
        }
        if yy >= 0 {
            for year in 0..yy {
                days += if is_leap(year + 1) { 366 } else { 365 };
            }
        } else {
            for year in yy..0 {
                days -= if is_leap(year + 1) { 366 } else { 365 };
            }
        }
        days
    }

    /// Offset between the port's day count and the naive reference,
    /// computed once from the formula at 0000-03-01:
    /// 365*6800 + 0 + 1700 - 68 + 17 - 32045 + 1 = 2451605.
    const EPOCH_OFFSET: i32 = 2451605;

    fn read(regs: [u8; 7]) -> (u32, u32, i32) {
        let _guard = SLOT_LOCK.lock().unwrap();
        unsafe {
            MOCK_REGS = regs;
            MOCK_STATUS = 0;
            RTC_READ_REGS = mock_rtc_read;
        }
        let mut days = 0u32;
        let mut secs = 0u32;
        let rc = unsafe { rtc_read_time(&mut days, &mut secs, 0, 0) };
        unsafe {
            RTC_READ_REGS = crate::drivers::i2c::pmu_i2c_read_regs;
        }
        (days, secs, rc)
    }

    #[test]
    fn bcd_decode() {
        assert_eq!(bcd_to_bin(0x00), 0);
        assert_eq!(bcd_to_bin(0x09), 9);
        assert_eq!(bcd_to_bin(0x10), 10);
        assert_eq!(bcd_to_bin(0x59), 59);
        assert_eq!(bcd_to_bin(0x99), 99);
        // 0x9a and above clamp to 99.
        assert_eq!(bcd_to_bin(0x9a), 99);
        assert_eq!(bcd_to_bin(0xff), 99);
    }

    #[test]
    fn valid_dates_match_naive_gregorian() {
        // (year2, month, day) cases across leap boundaries.
        let cases: [(i32, i32, i32); 12] = [
            (0, 3, 1),
            (0, 1, 1),
            (0, 2, 28),
            (0, 2, 29), // year 0 is leap (divisible by 400)
            (0, 12, 31),
            (24, 2, 28),
            (24, 2, 29),
            (24, 3, 1),
            (23, 2, 28),
            (23, 3, 1),
            (99, 12, 31),
            (70, 1, 1),
        ];
        for &(y, m, d) in &cases {
            let regs = [0x00, 0x00, 0x00, 0x00, to_bcd(d), to_bcd(m), to_bcd(y)];
            let (days, secs, rc) = read(regs);
            assert_eq!(rc, 0);
            assert_eq!(secs, 0);
            let expect = (ref_days_since_mar1_year0(y, m, d) + EPOCH_OFFSET) as u32;
            assert_eq!(
                days, expect,
                "day count mismatch for {y:02}-{m:02}-{d:02}"
            );
        }
    }

    fn to_bcd(v: i32) -> u8 {
        (((v / 10) << 4) | (v % 10)) as u8
    }

    #[test]
    fn seconds_of_day() {
        let (days, secs, rc) = read([0x58, 0x59, 0x23, 0x04, 0x29, 0x02, 0x24]);
        assert_eq!(rc, 0);
        assert_eq!(secs, (23 * 3600 + 59 * 60 + 58) as u32);
        let expect = (ref_days_since_mar1_year0(24, 2, 29) + EPOCH_OFFSET) as u32;
        assert_eq!(days, expect);
        // 00:00:00.
        let (_, secs, _) = read([0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x24]);
        assert_eq!(secs, 0);
    }

    #[test]
    fn reader_called_with_bank_zero() {
        let guard = install_mock([0x00, 0x00, 0x12, 0x00, 0x15, 0x06, 0x24], 0);
        let mut days = 0u32;
        let mut secs = 0u32;
        let rc = unsafe { rtc_read_time(&mut days, &mut secs, 0, 0) };
        assert_eq!(rc, 0);
        unsafe {
            assert_eq!(MOCK_CALLS, 1);
            assert_eq!(MOCK_LAST_BANK, 0);
        }
        assert_eq!(secs, (12 * 3600) as u32);
        restore(guard);
    }

    #[test]
    fn read_error_returns_minus5_but_still_converts() {
        // Failing reader leaves the buffer untouched: the seed words
        // (the original's saved r2/r3 slots) are what gets converted.
        let guard = install_mock([0; 7], 9);
        let mut days = 0u32;
        let mut secs = 0u32;
        let rc = unsafe { rtc_read_time(&mut days, &mut secs, 0x44332211, 0x77665588) };
        assert_eq!(rc, -5);
        // LE seeds -> buf = [0x11,0x22,0x33,0x44, 0x88,0x55,0x66,0x77],
        // so secs = bcd(0x33)*3600 + bcd(0x22)*60 + bcd(0x11)
        // = 33*3600 + 22*60 + 11.
        assert_eq!(secs, (33 * 3600 + 22 * 60 + 11) as u32);
        let expect = convert(&[0x11, 0x22, 0x33, 0x44, 0x88, 0x55, 0x66, 0x77]);
        assert_eq!((days, secs), expect);
        restore(guard);
    }

    #[test]
    fn default_stub_fails_closed() {
        let _guard = SLOT_LOCK.lock().unwrap();
        // No mock installed: the shipped chain (pmu_i2c_read_regs ->
        // i2c's PMU_READ_REGS stub) reports the bad-bank code 9, and
        // the ROM_KERNEL default stubs make the lock pair a no-op.
        let mut days = 0u32;
        let mut secs = 0u32;
        let rc = unsafe { rtc_read_time(&mut days, &mut secs, 0, 0) };
        assert_eq!(rc, -5);
        // Zero buffer converts deterministically: month 0 -> adj 1,
        // year 6799, mp 9, day 0.
        let expect = convert(&[0; 8]);
        assert_eq!((days, secs), expect);
    }

    #[test]
    fn retained_pre_port_stub_still_reports_bad_bank() {
        // The pre-port stub is kept for host tests: driven through the
        // slot it fails closed exactly like the shipped chain's stub.
        let guard = install_mock([0; 7], 0);
        unsafe {
            RTC_READ_REGS = rtc_read_stub;
            let mut days = 0u32;
            let mut secs = 0u32;
            let rc = rtc_read_time(&mut days, &mut secs, 0, 0);
            assert_eq!(rc, -5);
            assert_eq!(MOCK_CALLS, 0, "the stub never reaches the mock");
        }
        restore(guard);
    }

    #[test]
    fn shipped_default_reads_through_the_ported_i2c_entry() {
        // RTC_READ_REGS left at its shipped default (the port); the
        // recording mock sits one slot deeper, at i2c's PMU_READ_REGS
        // (FUN_0836d698's stand-in). Lock order: this module's
        // SLOT_LOCK, then i2c's OPS_LOCK (no other path takes both).
        let guard = SLOT_LOCK.lock().unwrap();
        let i2c_guard = crate::drivers::i2c::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe extern "C" fn mock_pmu_read(bank: u32, buf: *mut u8) -> i32 {
            assert_eq!(bank, 0);
            core::ptr::copy_nonoverlapping(
                [0x58, 0x59, 0x23, 0x04, 0x29, 0x02, 0x24].as_ptr(),
                buf,
                7,
            );
            0
        }
        unsafe {
            core::ptr::addr_of_mut!(crate::drivers::i2c::PMU_READ_REGS)
                .write(mock_pmu_read);
            let mut days = 0u32;
            let mut secs = 0u32;
            let rc = rtc_read_time(&mut days, &mut secs, 0, 0);
            core::ptr::addr_of_mut!(crate::drivers::i2c::PMU_READ_REGS)
                .write(crate::drivers::i2c::pmu_read_regs_stub);
            assert_eq!(rc, 0);
            assert_eq!(secs, (23 * 3600 + 59 * 60 + 58) as u32);
            let expect = (ref_days_since_mar1_year0(24, 2, 29) + EPOCH_OFFSET) as u32;
            assert_eq!(days, expect);
        }
        drop(i2c_guard);
        drop(guard);
    }

    #[test]
    fn wild_bcd_does_not_panic() {
        // Months above 14 wrap the unsigned (14 - month) / 12 into a
        // huge quotient; all arithmetic must wrap, not trip debug
        // overflow checks.
        for m in [0x13u8, 0x32, 0x99, 0x9a, 0xff] {
            let buf = [0xff, 0xff, 0xff, 0xff, 0xff, m, 0xff, 0xff];
            let _ = convert(&buf);
        }
        // Clamped month 99 through the full entry point.
        let (_, _, rc) = read([0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99]);
        assert_eq!(rc, 0);
    }

    #[test]
    fn rtc_context_handle_uses_the_target_layout_offsets() {
        assert_eq!(core::mem::offset_of!(RtcContextOwner, rtc_context), 0xf00);
        assert_eq!(core::mem::offset_of!(RtcContext, handle), 0x0c);

        let first = RtcContext { reserved: [0x11; 0x0c], handle: 0x1122_3344 };
        let second = RtcContext { reserved: [0x22; 0x0c], handle: 0xaabb_ccdd };
        let mut owner = RtcContextOwner {
            reserved: [0xa5; 0xf00],
            rtc_context: &first,
        };

        assert_eq!(unsafe { rtc_context_handle(&owner) }, first.handle);
        owner.rtc_context = &second;
        assert_eq!(unsafe { rtc_context_handle(&owner) }, second.handle);
    }

    #[test]
    fn rtc_context_handle_only_reads_the_pointer_chain() {
        let nested = RtcContext { reserved: [0x3c; 0x0c], handle: 0xfeed_beef };
        let owner = RtcContextOwner {
            reserved: [0x5a; 0xf00],
            rtc_context: &nested,
        };
        let nested_reserved = nested.reserved;
        let owner_reserved = owner.reserved;

        assert_eq!(unsafe { rtc_context_handle(&owner) }, 0xfeed_beef);
        assert_eq!(nested.reserved, nested_reserved);
        assert_eq!(nested.handle, 0xfeed_beef);
        assert_eq!(owner.reserved, owner_reserved);
        assert!(core::ptr::eq(owner.rtc_context, &nested));
    }

    #[test]
    fn rtc_static_time_pair_places_the_adjacent_words_in_abi_order() {
        let mut outputs = [0xcccc_cccc; 4];
        let rc = unsafe { rtc_static_time_pair(&mut outputs[1], &mut outputs[3]) };

        assert_eq!(rc, 0);
        assert_eq!(
            outputs,
            [
                0xcccc_cccc,
                RTC_STATIC_TIME_PAIR[0],
                0xcccc_cccc,
                RTC_STATIC_TIME_PAIR[1],
            ]
        );
    }

    #[test]
    fn rtc_static_time_pair_does_not_modify_its_read_only_source() {
        let source_before = RTC_STATIC_TIME_PAIR;
        let mut days = 0;
        let mut secs = 0;

        assert_eq!(unsafe { rtc_static_time_pair(&mut days, &mut secs) }, 0);
        assert_eq!(RTC_STATIC_TIME_PAIR, source_before);
        assert_eq!((days, secs), (source_before[0], source_before[1]));
    }
}

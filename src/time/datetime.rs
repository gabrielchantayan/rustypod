//! The retailOS **packed calendar record** and its Unix-timestamp
//! converter: `FUN_08093c38` @ 0x08093c38.
//!
//! This is a second, entirely separate time stack from the ADS `struct tm`
//! one in `mktime.rs`/`localtime.rs`. Where `struct tm` is nine `i32`s,
//! this record is ten bytes of byte-wide fields with a 16-bit year, and it
//! is the shape the 0x0807exxx / 0x08093xxx calendar helpers all take.
//!
//! # The record
//!
//! Recovered from the three functions that touch it — the converter here,
//! the lexicographic comparator `FUN_08093af8` @ 0x08093af8 and the day
//! -number helper `FUN_0807ea68` @ 0x0807ea68:
//!
//! ```text
//! +0x00  u8   second      (converter, comparator)
//! +0x01  u8   minute      (converter, comparator)
//! +0x02  u8   hour        (converter, comparator)
//! +0x03  u8   day of month
//! +0x04  u8   month       (1 = January)
//! +0x05  u8   padding — no reader anywhere
//! +0x06  u16  year        (full year, `ldrh`)
//! +0x08  u8   weekday     — an OUT field: 0x0807ea68 stores the day
//!                           number mod 7 here on every call
//! +0x09  u8   padding
//! ```
//!
//! # Verified call-site count
//!
//! **45 `bl` and 1 predicated `b`** reach 0x08093c38, counted by decoding
//! every ARM B/BL word in `work/firmware/osos.dec` (load base 0x08000000)
//! and resolving each target — not a Ghidra xref count. The lone `b` is
//! conditional, i.e. a predicated tail call, not a veneer.
//!
//! # Extent: 104 bytes, not the 92 `functions.csv` reports
//!
//! 0x08093c38..0x08093ca0. The 92 covers the 23 instructions and stops at
//! the `pop` @ 0x08093c90; it drops the three literal-pool words that
//! follow, which this function's own `ldr rN, [pc, ...]` instructions
//! reach:
//!
//! ```text
//! 0x08093c94  0x083e2e3e   &FLOOR      (comparator's second argument)
//! 0x08093c98  0xfff506c5   -719163     (Rata Die -> Unix day bias)
//! 0x08093c9c  0x00015180   86400       (seconds per day)
//! ```
//!
//! The next function opens at 0x08093ca0 with `push {r4, lr}`.
//!
//! # Algorithm
//!
//! ```text
//! if (datetime_compare(dt, FLOOR) < 0) return 0;
//! days = datetime_day_number(dt);            /* also sets dt->weekday */
//! return (days - 719163) * 86400
//!      + dt->hour * 3600 + dt->minute * 60 + dt->second;
//! ```
//!
//! 719163 is the day number of 1970-01-01 under 0x0807ea68's numbering
//! (proleptic Gregorian, 0001-01-01 = day 1), so the subtraction turns a
//! Rata-Die day count into days since the Unix epoch. The original
//! strength-reduces both remaining multiplies: `hour * 3600` is
//! `smulbb r1, hour, #225` then `add r0, r0, r1, lsl #4`, and
//! `minute * 60` is `rsb r1, min, min, lsl #4` (= min * 15) then
//! `add r0, r0, r1, lsl #2`. Every add is flagless ARM arithmetic, so the
//! port wraps rather than panicking on overflow.
//!
//! `FUN_0807ea68` is Rata Die proper:
//! `365*(y-1) + (y-1)/4 - (y-1)/100 + (y-1)/400 + (367*month - 362)/12
//! + leap_adjust(y, month) + day`, with 365 and 367 in its own literal
//! pool @ 0x0807eaf4/0x0807eaf8, the divisions through `__rt_udiv` @
//! 0x08036f14 and the February correction from `FUN_08086e00`. It then
//! divides the result by 7 and writes the remainder to `dt->weekday`.
//!
//! # The floor record is unreadable, so it stays a pointer
//!
//! The comparator's second argument is the fixed record at **runtime**
//! 0x083e2e3e. Under this image's scatterload skew (`__scatterload` @
//! 0x080046e0 memmoves 0xa0fc88 bytes from image 0x0800aed8 down to
//! runtime 0x08000000, so image address = runtime address + 0xaed8 — see
//! the region-survey block in names.yaml) its bytes live at image
//! 0x083f1d16, which falls inside the still-undecrypted zero run
//! 0x083ee1c1-0x083f25ec. They read as zeros because that region was
//! never decrypted, not because they are zero.
//!
//! Everything about the function says the record is 1970-01-01 00:00:00 —
//! it is the value below which the converter clamps to 0, and 0 is exactly
//! the Unix timestamp of that instant — but this port does not write that
//! guess down as data. [`DATETIME_FLOOR`] holds the **address**, which is
//! what the original's literal holds, and the comparison goes through the
//! [`DATETIME_OPS`] dispatch. On target with the stock comparator wired in
//! that is byte-for-byte the original's behavior whatever the record says.
//!
//! # Deviations
//!
//! - `FUN_08093af8` (comparator) is not ported; it dispatches through
//!   [`DATETIME_OPS`], the house pattern
//!   (see `app/iap_packet.rs`, `heap/alloc_core.rs`).
//! - `FUN_0807ea68` (day number) IS ported as
//!   [`crate::time::day_number::datetime_day_number`] and is the wired
//!   default; the comparator's wired default returns 0 — "at or after
//!   the floor" — so the arithmetic path stays live with no hooks
//!   installed and no dereference of the unmapped host address in
//!   [`DATETIME_FLOOR`].

/// The packed calendar record the 0x0807exxx / 0x08093xxx helpers take.
///
/// Named fields, not byte offsets: on the ARM target this lays out
/// exactly as the original's ten bytes (`year` is 2-aligned at +6), and
/// it lays out the same on the host, so the tests exercise the real
/// shape.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    /// +0x00 — seconds.
    pub second: u8,
    /// +0x01 — minutes.
    pub minute: u8,
    /// +0x02 — hours.
    pub hour: u8,
    /// +0x03 — day of month.
    pub day: u8,
    /// +0x04 — month, 1 = January.
    pub month: u8,
    /// +0x05 — padding; nothing in the image reads it.
    pub reserved: u8,
    /// +0x06 — full year (`ldrh`, so 0..65535).
    pub year: u16,
    /// +0x08 — weekday, written by the day-number helper.
    pub weekday: u8,
    /// +0x09 — padding.
    pub reserved2: u8,
}

/// Day number of 1970-01-01 under `FUN_0807ea68`'s Rata Die numbering —
/// the literal 0xfff506c5 = -719163 @ 0x08093c98, added rather than
/// subtracted by the original.
pub const UNIX_EPOCH_DAY_NUMBER: i32 = 719163;

/// 86400, the literal @ 0x08093c9c.
pub const SECONDS_PER_DAY: i32 = 86400;

/// 3600, formed by the original as `smulbb hour, #225` << 4.
pub const SECONDS_PER_HOUR: i32 = 3600;

/// 60, formed by the original as `rsb r1, min, min, lsl #4` << 2.
pub const SECONDS_PER_MINUTE: i32 = 60;

/// The fixed record [`datetime_to_unix_seconds`] refuses to go below:
/// **runtime address 0x083e2e3e**, the literal @ 0x08093c94.
///
/// Its ten bytes are not recoverable from `osos.dec` (module header), so
/// this is deliberately a pointer and never a value. On target it aims at
/// the real record; on the host it is only ever handed to the
/// [`DATETIME_OPS`] comparator, which the default stub never
/// dereferences.
pub static mut DATETIME_FLOOR: *const DateTime = 0x083e2e3e as *const DateTime;

/// Indirect dispatch for this converter's two unported callees.
#[derive(Clone, Copy)]
pub struct DateTimeOps {
    /// `FUN_08093af8` @ 0x08093af8 (8 `bl` call sites): lexicographic
    /// compare of two records, most significant field first — year
    /// (`ldrh` +6), month, day, hour, minute, second. It returns the
    /// difference of the first pair of fields that differ, as
    /// `left_field - right_field`, and 0 when all six match; the
    /// converter only tests the sign. Default: 0.
    pub compare: unsafe extern "C" fn(left: *const DateTime, right: *const DateTime) -> i32,
    /// `FUN_0807ea68` @ 0x0807ea68 (25 `bl` call sites): the Rata Die day
    /// number of the record's year/month/day, which it also reduces mod 7
    /// into `dt->weekday`. Default: the ported
    /// [`crate::time::day_number::datetime_day_number`].
    pub day_number: unsafe extern "C" fn(dt: *mut DateTime) -> i32,
}

unsafe extern "C" fn compare_stub(_left: *const DateTime, _right: *const DateTime) -> i32 {
    0
}

/// Wired defaults: the documented comparator stub and the ported
/// day-number helper.
pub(crate) const DEFAULT_DATETIME_OPS: DateTimeOps = DateTimeOps {
    compare: compare_stub,
    day_number: super::day_number::datetime_day_number,
};

/// The active ops. Host tests swap in real implementations and restore.
pub static mut DATETIME_OPS: DateTimeOps = DEFAULT_DATETIME_OPS;

/// Volatile read so LLVM cannot fold the default stubs in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn datetime_ops() -> DateTimeOps {
    core::ptr::read_volatile(core::ptr::addr_of!(DATETIME_OPS))
}

/// datetime_to_unix_seconds — original: `FUN_08093c38` @ 0x08093c38
/// (**104 bytes, 0x08093c38..0x08093ca0**, including the three trailing
/// literal-pool words; 45 `bl` and 1 predicated `b` call sites, both
/// counted by decoding every branch word in `osos.dec`).
///
/// Converts the packed record to a Unix timestamp, clamping to 0 for
/// anything below the fixed floor record @ 0x083e2e3e:
///
/// ```text
/// if (compare(dt, FLOOR) < 0) return 0;
/// return (day_number(dt) - 719163) * 86400
///      + hour * 3600 + minute * 60 + second;
/// ```
///
/// The day-number call is a side-effecting one — it rewrites
/// `dt->weekday` — which is why this takes `*mut`, as the original does
/// (it passes its own incoming `r0` straight through).
///
/// All arithmetic wraps: the original is flagless ARM `add`/`mul`.
///
/// # Safety
///
/// `dt` must point at a readable, writable [`DateTime`]. The installed
/// [`DATETIME_OPS`] comparator must accept [`DATETIME_FLOOR`] as its
/// right-hand argument.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn datetime_to_unix_seconds(dt: *mut DateTime) -> i32 {
    let ops = datetime_ops();

    let floor = core::ptr::read_volatile(core::ptr::addr_of!(DATETIME_FLOOR));
    if (ops.compare)(dt, floor) < 0 {
        return 0;
    }

    let days = (ops.day_number)(dt);
    let seconds = days
        .wrapping_sub(UNIX_EPOCH_DAY_NUMBER)
        .wrapping_mul(SECONDS_PER_DAY);

    seconds
        .wrapping_add((*dt).hour as i32 * SECONDS_PER_HOUR)
        .wrapping_add((*dt).minute as i32 * SECONDS_PER_MINUTE)
        .wrapping_add((*dt).second as i32)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    /// Serializes the tests that write the shared dispatch slots.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// The floor the host tests stand in for the unreadable record @
    /// 0x083e2e3e. Its value is a test fixture only — the port never
    /// bakes a floor in (module header).
    static mut TEST_FLOOR: DateTime = DateTime {
        second: 0,
        minute: 0,
        hour: 0,
        day: 1,
        month: 1,
        reserved: 0,
        year: 1970,
        weekday: 0,
        reserved2: 0,
    };

    fn dt(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> DateTime {
        DateTime {
            second,
            minute,
            hour,
            day,
            month,
            reserved: 0,
            year,
            weekday: 0xff,
            reserved2: 0,
        }
    }

    /// Faithful re-implementation of `FUN_08093af8` @ 0x08093af8:
    /// lexicographic compare, most significant field first, returning
    /// the difference of the first differing pair.
    unsafe extern "C" fn compare_real(left: *const DateTime, right: *const DateTime) -> i32 {
        let (l, r) = (&*left, &*right);
        for (a, b) in [
            (l.year as i32, r.year as i32),
            (l.month as i32, r.month as i32),
            (l.day as i32, r.day as i32),
            (l.hour as i32, r.hour as i32),
            (l.minute as i32, r.minute as i32),
            (l.second as i32, r.second as i32),
        ] {
            if a != b {
                return a - b;
            }
        }
        0
    }

    /// Faithful re-implementation of `FUN_0807ea68` @ 0x0807ea68: the
    /// Rata Die day number, plus the weekday side effect.
    unsafe extern "C" fn day_number_real(dt: *mut DateTime) -> i32 {
        let d = &mut *dt;
        let y = d.year as i32 - 1;
        let leap_adjust = if d.month <= 2 {
            0
        } else if (d.year % 4 == 0 && d.year % 100 != 0) || d.year % 400 == 0 {
            -1
        } else {
            -2
        };
        let days = 365 * y + y / 4 - y / 100 + y / 400
            + (367 * d.month as i32 - 362) / 12
            + leap_adjust
            + d.day as i32;
        d.weekday = (days % 7) as u8;
        days
    }

    /// Installs the real comparator/day-number pair and the fixture
    /// floor; returns the guard that restores them.
    fn install() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!(DATETIME_OPS),
                DateTimeOps { compare: compare_real, day_number: day_number_real },
            );
            ptr::write_volatile(
                ptr::addr_of_mut!(DATETIME_FLOOR),
                ptr::addr_of!(TEST_FLOOR),
            );
        }
        guard
    }

    fn restore(guard: std::sync::MutexGuard<'static, ()>) {
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!(DATETIME_OPS), DEFAULT_DATETIME_OPS);
            ptr::write_volatile(
                ptr::addr_of_mut!(DATETIME_FLOOR),
                0x083e2e3e as *const DateTime,
            );
        }
        drop(guard);
    }

    /// The record must be exactly the original's ten bytes with `year`
    /// as a halfword at +6 — the whole port rests on that.
    #[test]
    fn the_record_matches_the_original_layout() {
        assert_eq!(core::mem::size_of::<DateTime>(), 10);
        let d = dt(0, 0, 0, 0, 0, 0);
        let base = ptr::addr_of!(d) as usize;
        assert_eq!(ptr::addr_of!(d.second) as usize - base, 0x00);
        assert_eq!(ptr::addr_of!(d.minute) as usize - base, 0x01);
        assert_eq!(ptr::addr_of!(d.hour) as usize - base, 0x02);
        assert_eq!(ptr::addr_of!(d.day) as usize - base, 0x03);
        assert_eq!(ptr::addr_of!(d.month) as usize - base, 0x04);
        assert_eq!(ptr::addr_of!(d.year) as usize - base, 0x06);
        assert_eq!(ptr::addr_of!(d.weekday) as usize - base, 0x08);
    }

    /// The epoch itself: the floor compares equal, so the clamp does not
    /// fire, and the arithmetic must land on 0.
    #[test]
    fn the_epoch_converts_to_zero_through_the_arithmetic_path() {
        let guard = install();
        let mut d = dt(1970, 1, 1, 0, 0, 0);
        assert_eq!(unsafe { datetime_to_unix_seconds(&mut d) }, 0);
        assert_eq!(d.weekday, 4, "1970-01-01 is a Thursday");
        restore(guard);
    }

    /// Known timestamps, including a leap day, a century non-leap year
    /// (2100) and a post-2038 date that wraps the i32 exactly as the
    /// original's flagless `mul`/`add` do.
    #[test]
    fn known_instants_convert_exactly() {
        let guard = install();
        for (mut d, expected) in [
            (dt(1970, 1, 1, 0, 0, 1), 1i32),
            (dt(1970, 1, 1, 0, 1, 0), 60),
            (dt(1970, 1, 1, 1, 0, 0), 3600),
            (dt(1970, 1, 2, 0, 0, 0), 86400),
            (dt(2000, 2, 29, 12, 0, 0), 951825600),
            (dt(2001, 9, 9, 1, 46, 40), 1_000_000_000),
            (dt(2009, 9, 9, 0, 0, 0), 1_252_454_400),
            (dt(2038, 1, 19, 3, 14, 7), i32::MAX),
            (dt(2038, 1, 19, 3, 14, 8), i32::MIN),
            (dt(2100, 3, 1, 0, 0, 0), 4_107_542_400u32 as i32),
        ] {
            assert_eq!(
                unsafe { datetime_to_unix_seconds(&mut d) },
                expected,
                "{d:?}"
            );
        }
        restore(guard);
    }

    /// Anything strictly below the floor clamps to 0 without running the
    /// day-number helper — the original's `blt` skips it, so the weekday
    /// side effect must not happen either.
    #[test]
    fn dates_below_the_floor_clamp_to_zero_and_skip_the_day_number_call() {
        let guard = install();
        // The last entry differs from the floor only in the month field,
        // so the comparator has to walk past `year` to see it.
        let below_by_month = DateTime { month: 0, ..dt(1970, 1, 1, 0, 0, 0) };
        for mut d in [
            dt(1969, 12, 31, 23, 59, 59),
            dt(1969, 1, 1, 0, 0, 0),
            dt(0, 0, 0, 0, 0, 0),
            below_by_month,
        ] {
            assert_eq!(unsafe { datetime_to_unix_seconds(&mut d) }, 0, "{d:?}");
            assert_eq!(d.weekday, 0xff, "day_number must not have run: {d:?}");
        }
        restore(guard);
    }

    /// The clamp is on `< 0` only: an equal record and every record above
    /// the floor take the arithmetic path.
    #[test]
    fn the_clamp_is_strict() {
        let guard = install();
        let mut equal = dt(1970, 1, 1, 0, 0, 0);
        assert_eq!(unsafe { datetime_to_unix_seconds(&mut equal) }, 0);
        assert_eq!(equal.weekday, 4, "the equal case runs day_number");

        let mut above = dt(1970, 1, 1, 0, 0, 1);
        assert_eq!(unsafe { datetime_to_unix_seconds(&mut above) }, 1);
        restore(guard);
    }

    /// Time-of-day fields are added with their full byte range, no
    /// validation — the original just multiplies whatever bytes it finds.
    #[test]
    fn out_of_range_time_fields_are_added_verbatim() {
        let guard = install();
        let mut d = dt(1970, 1, 1, 255, 255, 255);
        let expected = 255 * 3600 + 255 * 60 + 255;
        assert_eq!(unsafe { datetime_to_unix_seconds(&mut d) }, expected);
        restore(guard);
    }

    /// With no hooks installed the wired defaults must still produce the
    /// documented result rather than dereferencing the target-only floor
    /// address: compare 0 (not below), and the now-ported day number
    /// computes the real Rata Die value and weekday — the epoch record
    /// lands exactly on `UNIX_EPOCH_DAY_NUMBER`, so only the time-of-day
    /// terms contribute.
    #[test]
    fn the_wired_defaults_run_the_arithmetic_without_touching_the_floor() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut d = dt(1970, 1, 1, 2, 3, 4);
        let expected = 2 * 3600 + 3 * 60 + 4;
        assert_eq!(unsafe { datetime_to_unix_seconds(&mut d) }, expected);
        assert_eq!(d.weekday, 4, "the ported day_number writes the weekday");
        drop(guard);
    }
}

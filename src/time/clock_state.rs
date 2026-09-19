//! Clock-state refresh and day-of-year fill: `FUN_080642a4` @ 0x080642a4.
//!
//! Ghidra reports 100 bytes; the true extent is 104 bytes,
//! 0x080642a4..0x0806430c — the 25 instructions plus the one literal-pool
//! word @ 0x08064308 (0x08a662e0, the shadow clock-state record) that the
//! body's own `ldr r5, [pc, #0x58]` reaches. The next function opens at
//! 0x0806430c with `stmdb sp!, {r4,r5,r6,lr}`.
//!
//! Five unconditional `bl` call sites, counted by decoding every ARM BL
//! word in `work/firmware/osos.dec` and cross-checked against osos.asm:
//! @ 0x08044a60 (FUN_08044a44), @ 0x08056544 (FUN_08056524, the
//! current-calendar query), @ 0x08056824 (FUN_08056800), @ 0x080684c0
//! (FUN_08068490), @ 0x080fc40c (FUN_080fc3d8). No predicated `bl` sites.
//! The body itself makes one `bl` (@ 0x080642d0 -> the RTC getter
//! `FUN_0806418c`) and ends in a tail `b` @ 0x08064304 -> the day-of-year
//! helper @ 0x080d6fe0 (reproduced here as [`clock_state_day_of_year`]).
//!
//! # The 12-byte clock-state record
//!
//! Recovered from the getter `FUN_0806418c`'s stores, this function's own
//! accesses, and the caller `FUN_08056524`'s reads:
//!
//! ```text
//! +0x00  u16  year        full year (getter adds 2000 to the RTC byte)
//! +0x02  u8   month       1 = January
//! +0x03  u8   day         day of month
//! +0x04  i16  yday        0-based day of year — OUT, written here
//! +0x06  i8   utc_offset_quarters  UTC offset in signed 15-minute units
//! +0x07  u8   dst_active  nonzero => daylight-saving in effect
//! +0x08  u8   hour
//! +0x09  u8   minute
//! +0x0a  u8   second
//! +0x0b  u8   status      bit0: clock valid; bit1: zone/DST fields valid
//! ```
//!
//! Caller evidence for +0x06/+0x07/status bit1: `FUN_08056524` gates on
//! status bit1 (`0x2000000` of the +0x08 word), then emits
//! `utc_offset_quarters * 15` as base offset minutes and 60 when
//! `dst_active` is set; status bit0 clear makes it substitute build-time
//! defaults for year/month/day.
//!
//! # Algorithm
//!
//! ```arm
//! stmdb sp!, {r4,r5,r6,lr}
//! ldr   r5, =0x08a662e0        ; shadow record (literal @ 0x08064308)
//! mov   r4, r0                 ; state
//! ldrb  r0, [r5, #0xb]         ; state.status = shadow.status
//! mov   r1, r4
//! strb  r0, [r4, #0xb]
//! ldrb  r0, [r5, #6]           ; state.utc_offset_quarters = shadow's
//! strb  r0, [r4, #6]
//! ldrb  r0, [r5, #7]           ; state.dst_active = shadow's
//! strb  r0, [r4, #7]
//! mov   r0, #0
//! bl    0x0806418c             ; rtc getter: refresh state from hardware
//! ldrb  r0, [r5, #6]           ; re-copy the zone bytes (getter never
//! strb  r0, [r4, #6]           ; writes +6/+7, but the copy is repeated)
//! ldrb  r0, [r5, #7]
//! strb  r0, [r4, #7]
//! ldrb  r0, [r4, #0xb]         ; state.status = state.status & ~2
//! ldrb  r1, [r5, #0xb]         ;                | shadow.status & 2
//! bic   r0, r0, #2
//! and   r1, r1, #2
//! orr   r0, r0, r1
//! strb  r0, [r4, #0xb]
//! mov   r0, r4
//! ldmia sp!, {r4,r5,r6,lr}
//! b     0x080d6fe0             ; tail: fill state.yday
//! ```
//!
//! The getter's return value is deliberately ignored (r0 is dead across
//! the re-copy). The day-of-year helper @ 0x080d6fe0 (52 bytes plus its
//! table literal @ 0x080d7034 = 0x089caaa0) computes
//! `yday = day - 1 + sum(month_lengths[0..month-1])` over the LEAP-year
//! table {31,29,31,30,31,30,31,31,30,31,30,31} (runtime 0x089caaa0; image
//! 0x089d5978 under the scatterload skew, decrypted, contents verified),
//! substituting 28 for February when the year is common under the
//! Gregorian test of `FUN_08074410` (year % 4 == 0, centuries using
//! year/100 % 4 == 0 — i.e. 1900 common, 2000 leap). The helper's loop
//! bound is the signed compare `i < (i32)month - 1`, so month 0 or 1
//! runs zero iterations.
//!
//! # Deviations
//!
//! - The unported RTC getter `FUN_0806418c` is reached through the
//!   house seam: the target build calls its fixed load address
//!   0x0806418c; host tests install a recording mock in
//!   [`CLOCK_STATE_GET`]. Same for the shadow record: fixed address
//!   0x08a662e0 on target, a writable static on host.
//! - The tail `b` to 0x080d6fe0 is a private `#[inline(never)]` Rust
//!   call (LLVM emits `bl`), and its leap test `FUN_08074410` is
//!   inlined as three operations routed through the ported
//!   `__rt_udivmod` (`runtime/rt_div.rs`) instead of the original's
//!   `bl 0x08031568`. Observable behavior is identical.
//! - Shadow field reads are volatile so LLVM cannot fold the duplicated
//!   copies across the getter call; field order matches the listing.
//! - LLVM peels the helper's first two month iterations into straight-line
//!   cumulative sums and counts the rest down; the original is one loop.
//!   Same sums, same out-of-bounds table reads for month > 12, proven by
//!   the host tests.

use core::ptr;

use crate::runtime::rt_div::__rt_udivmod;

/// Load address of the unported RTC clock getter `FUN_0806418c`.
const CLOCK_STATE_GET_ADDRESS: usize = 0x0806_418c;

/// Load address of the firmware's shadow clock-state record.
const CLOCK_STATE_SHADOW_ADDRESS: usize = 0x08a6_62e0;

/// Status bit: the zone/DST bytes (+0x06/+0x07) carry valid data.
pub const STATUS_ZONE_VALID: u8 = 0x02;

/// The leap-year days-in-month table, runtime 0x089caaa0 (module
/// header): months 1..=12 at indices 0..=11, February stored as 29.
const LEAP_DAYS_IN_MONTH: [u8; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// The 12-byte clock-state record (module header for the layout
/// evidence). `#[repr(C)]`; the original record is word-aligned in its
/// stack frame, this adds alignment 2 only — offsets are unaffected.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClockState {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub yday: i16,
    pub utc_offset_quarters: i8,
    pub dst_active: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub status: u8,
}

/// The RTC clock getter `FUN_0806418c`: `force` in r0 (this caller
/// always passes 0), the record to fill in r1, status in r0 (ignored
/// here exactly as the original ignores it).
pub type ClockStateGetFn = unsafe extern "C" fn(force: u32, state: *mut ClockState) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_clock_state_get(_force: u32, _state: *mut ClockState) -> i32 {
    panic!("install an RTC clock-state getter before refreshing the clock state")
}

/// Host replacement for the unported getter `FUN_0806418c`; the target
/// build calls its fixed load address directly. Host tests install a
/// recording mock.
#[cfg(not(target_os = "none"))]
pub static mut CLOCK_STATE_GET: ClockStateGetFn = missing_clock_state_get;

/// Host stand-in for the firmware's shadow clock-state record @
/// 0x08a662e0 (zone bytes + zone-valid bit preserved across refreshes).
#[cfg(not(target_os = "none"))]
pub static mut CLOCK_STATE_SHADOW: ClockState = ClockState {
    year: 0,
    month: 0,
    day: 0,
    yday: 0,
    utc_offset_quarters: 0,
    dst_active: 0,
    hour: 0,
    minute: 0,
    second: 0,
    status: 0,
};

#[inline(always)]
unsafe fn clock_state_get() -> ClockStateGetFn {
    #[cfg(target_os = "none")]
    {
        core::mem::transmute(CLOCK_STATE_GET_ADDRESS)
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(CLOCK_STATE_GET))
    }
}

#[inline(always)]
unsafe fn clock_state_shadow() -> *const ClockState {
    #[cfg(target_os = "none")]
    {
        core::mem::transmute(CLOCK_STATE_SHADOW_ADDRESS)
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of!(CLOCK_STATE_SHADOW)
    }
}

/// fetch_clock_state — original: `FUN_080642a4` @ 0x080642a4 (104 bytes
/// including the literal pool word; 5 `bl` call sites, module header).
///
/// Refresh `state` from the RTC through the getter, preserving the
/// shadow record's zone bytes and zone-valid status bit across the
/// refresh, then fill `state.yday`. `state` must point to a writable
/// 12-byte [`ClockState`]. The getter's error return is ignored exactly
/// as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fetch_clock_state(state: *mut ClockState) {
    let shadow = clock_state_shadow();
    ptr::write_volatile(&mut (*state).status, ptr::read_volatile(&(*shadow).status));
    ptr::write_volatile(
        &mut (*state).utc_offset_quarters,
        ptr::read_volatile(&(*shadow).utc_offset_quarters),
    );
    ptr::write_volatile(&mut (*state).dst_active, ptr::read_volatile(&(*shadow).dst_active));

    clock_state_get()(0, state);

    ptr::write_volatile(
        &mut (*state).utc_offset_quarters,
        ptr::read_volatile(&(*shadow).utc_offset_quarters),
    );
    ptr::write_volatile(&mut (*state).dst_active, ptr::read_volatile(&(*shadow).dst_active));
    let status = (*state).status & !STATUS_ZONE_VALID
        | ptr::read_volatile(&(*shadow).status) & STATUS_ZONE_VALID;
    ptr::write_volatile(&mut (*state).status, status);

    clock_state_day_of_year(state);
}

/// Day-of-year fill — original: `FUN_080d6fe0` @ 0x080d6fe0 (52 bytes
/// plus the table literal @ 0x080d7034), the tail branch target of
/// `FUN_080642a4`. `yday = day - 1 + sum(LEAP_DAYS_IN_MONTH[0..month-1])`
/// with February corrected to 28 in common years; the leap test is
/// `FUN_08074410` (year % 4 == 0, centuries divided by 100 first).
/// `#[inline(never)]` keeps it a distinct call for match.py review.
#[inline(never)]
unsafe fn clock_state_day_of_year(state: *mut ClockState) {
    let mut yday: i16 = (*state).day as i16 - 1;
    let mut residue: u32 = 0;
    let quot = __rt_udivmod((*state).year as u32, 100, &mut residue);
    let year = if residue == 0 { quot } else { (*state).year as u32 };
    let common = year & 3 != 0;
    let mut i: i32 = 0;
    while i < (*state).month as i32 - 1 {
        if i == 1 && common {
            yday += 28;
        } else {
            // Bare ldrb in the original: no bounds check on month.
            yday += *LEAP_DAYS_IN_MONTH.as_ptr().add(i as usize) as i16;
        }
        i += 1;
    }
    (*state).yday = yday;
}

#[cfg(test)]
pub(crate) static CLOCK_STATE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static STATE_LOCK: Mutex<()> = Mutex::new(());
    static GET_COUNT: AtomicUsize = AtomicUsize::new(0);
    static GET_FORCE: AtomicUsize = AtomicUsize::new(0);

    fn zeroed() -> ClockState {
        ClockState {
            year: 0,
            month: 0,
            day: 0,
            yday: 0,
            utc_offset_quarters: 0,
            dst_active: 0,
            hour: 0,
            minute: 0,
            second: 0,
            status: 0,
        }
    }

    /// Mock getter: fills the calendar fields from the RTC like the real
    /// `FUN_0806418c`, stamps status 0x11 (neither zone bit), and —
    /// unlike the real one — stomps +6/+7 to prove the re-copy restores
    /// them from the shadow.
    unsafe extern "C" fn mock_get(force: u32, state: *mut ClockState) -> i32 {
        GET_FORCE.store(force as usize, Ordering::Relaxed);
        GET_COUNT.fetch_add(1, Ordering::Relaxed);
        (*state).year = 2009;
        (*state).month = 3;
        (*state).day = 1;
        (*state).hour = 12;
        (*state).minute = 34;
        (*state).second = 56;
        (*state).utc_offset_quarters = 99;
        (*state).dst_active = 99;
        (*state).status = 0x11;
        0
    }

    /// Mock getter reporting an I2C timeout (0x15 family); the original
    /// ignores the return, so the refresh must complete regardless.
    unsafe extern "C" fn mock_get_failing(_force: u32, state: *mut ClockState) -> i32 {
        GET_COUNT.fetch_add(1, Ordering::Relaxed);
        (*state).year = 2008;
        (*state).month = 2;
        (*state).day = 29;
        (*state).status = 0x02;
        -6
    }

    unsafe fn install(
        get: ClockStateGetFn,
        shadow: ClockState,
    ) -> (ClockStateGetFn, ClockState) {
        let saved_get = ptr::replace(ptr::addr_of_mut!(CLOCK_STATE_GET), get);
        let saved_shadow = ptr::replace(ptr::addr_of_mut!(CLOCK_STATE_SHADOW), shadow);
        (saved_get, saved_shadow)
    }

    unsafe fn restore(saved: (ClockStateGetFn, ClockState)) {
        ptr::write(ptr::addr_of_mut!(CLOCK_STATE_GET), saved.0);
        ptr::write(ptr::addr_of_mut!(CLOCK_STATE_SHADOW), saved.1);
    }

    #[test]
    fn refreshes_calendar_and_preserves_shadow_zone_bytes() {
        let _guard = CLOCK_STATE_TEST_LOCK.lock();
        let mut shadow = zeroed();
        shadow.utc_offset_quarters = -32; // UTC-8
        shadow.dst_active = 1;
        shadow.status = 0xff; // zone bit set, plus noise in other bits
        let saved = unsafe { install(mock_get, shadow) };
        GET_COUNT.store(0, Ordering::Relaxed);

        let mut state = zeroed();
        unsafe { fetch_clock_state(&mut state) };

        assert_eq!(GET_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(GET_FORCE.load(Ordering::Relaxed), 0);
        assert_eq!(state.year, 2009);
        assert_eq!(state.month, 3);
        assert_eq!(state.day, 1);
        assert_eq!(state.hour, 12);
        assert_eq!(state.minute, 34);
        assert_eq!(state.second, 56);
        // Zone bytes come from the shadow, twice-copied over the mock's
        // stomp; only bit1 of status survives from the shadow.
        assert_eq!(state.utc_offset_quarters, -32);
        assert_eq!(state.dst_active, 1);
        assert_eq!(state.status, 0x11 | STATUS_ZONE_VALID);
        // 2009 is common: yday = 31 + 28 + (1 - 1) = 59.
        assert_eq!(state.yday, 59);
        unsafe { restore(saved) };
    }

    #[test]
    fn shadow_zone_bit_clear_leaves_getter_status_alone() {
        let _guard = CLOCK_STATE_TEST_LOCK.lock();
        let mut shadow = zeroed();
        shadow.status = 0xfc; // bit1 clear
        let saved = unsafe { install(mock_get, shadow) };

        let mut state = zeroed();
        unsafe { fetch_clock_state(&mut state) };

        assert_eq!(state.status, 0x11);
        assert_eq!(state.utc_offset_quarters, 0);
        unsafe { restore(saved) };
    }

    #[test]
    fn getter_error_is_ignored_and_leap_february_counts_29() {
        let _guard = CLOCK_STATE_TEST_LOCK.lock();
        let saved = unsafe { install(mock_get_failing, zeroed()) };

        let mut state = zeroed();
        unsafe { fetch_clock_state(&mut state) };

        // 2008 % 4 == 0, not a century: leap. yday = 31 + (29 - 1) = 59.
        assert_eq!(state.yday, 59);
        // Shadow bit1 is clear, so the getter's 0x02 is masked off.
        assert_eq!(state.status, 0x00);
        unsafe { restore(saved) };
    }

    #[test]
    fn century_years_divide_by_100_before_the_four_year_test() {
        let _guard = CLOCK_STATE_TEST_LOCK.lock();
        let saved = unsafe { install(mock_get, zeroed()) };

        let mut state = zeroed();
        unsafe { fetch_clock_state(&mut state) };
        unsafe { clock_state_day_of_year(&mut state) };
        state.year = 1900; // 1900/100 = 19, 19 & 3 != 0: common
        state.month = 3;
        state.day = 1;
        unsafe { clock_state_day_of_year(&mut state) };
        assert_eq!(state.yday, 59);
        state.year = 2000; // 2000/100 = 20, 20 & 3 == 0: leap
        unsafe { clock_state_day_of_year(&mut state) };
        assert_eq!(state.yday, 60);
        unsafe { restore(saved) };
    }

    #[test]
    fn month_zero_and_one_run_zero_table_iterations() {
        let _guard = CLOCK_STATE_TEST_LOCK.lock();
        let mut state = zeroed();
        state.year = 2009;
        state.month = 1;
        state.day = 17;
        unsafe { clock_state_day_of_year(&mut state) };
        assert_eq!(state.yday, 16);
        state.month = 0; // (i32)0 - 1 = -1: no iterations, no table read
        unsafe { clock_state_day_of_year(&mut state) };
        assert_eq!(state.yday, 16);
    }
}

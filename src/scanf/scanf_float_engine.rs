//! Port of the scanf/strtod float input engine for the stock firmware's
//! scanf core (ARM ADS 1.0.1): the `%e`/`%f`/`%g` front-end that collects
//! the decimal digit strings and hands them to the back-end converter
//! ([`scanf_float_convert`] @ 0x08036018, ported in `scanf_float.rs`).
//!
//! Port:
//! - `scanf_float_engine` — original: `FUN_08036348` @ 0x08036348
//!   (1052 bytes, region to 0x08036763). This is the engine the
//!   `vsscanf` veneer @ 0x08033170 calls as
//!   `engine(0, input, consumed_out, &conv)` and the `SCANF_ENGINE`
//!   target for floats (see `scanf_helpers.rs`).
//!
//! Algorithm (recovered from the machine code, cross-checked against the
//! Ghidra decompile — which is WRONG in one place, see below):
//! 1. Skip leading whitespace via `conv.ctype`, reading through
//!    `conv.getc(input)`; `consumed` (r5) starts at -1 and is bumped
//!    before EVERY getc, so it is always the index of the last-read char
//!    (net consumed count after the final ungetc). EOF (-1) while
//!    skipping returns **0** — the machine code is `mvneq r0, #0`
//!    (0x080363b8); Ghidra's `return -1` is a mis-decompile.
//! 2. If `width > 0` and the char is `+`/`-`, consume it (`-` sets the
//!    internal NEGATIVE bit) and read the next char.
//! 3. Leading `0`s are consumed WITHOUT entering the mantissa buffer
//!    (they only set DIGITS_SEEN and advance `consumed_out`); a `0x`/`0X`
//!    after exactly one leading zero would dispatch to the hex-float
//!    veneer — see the stub note below.
//! 4. A decimal point sets the PAST_DOT bit; zeros immediately after a
//!    LEADING dot (before any mantissa digit) are consumed without being
//!    stored, each decrementing `frac_adjust`.
//! 5. Main loop while `width > 0`: one more decimal point sets PAST_DOT;
//!    digits are appended to the mantissa buffer (sign byte at [0],
//!    18 digit slots); each stored fraction digit decrements
//!    `frac_adjust`. Digits past the 18-slot limit are still consumed:
//!    silently dropped after the dot, or dropped with `frac_adjust += 1`
//!    before it (keeping the value's magnitude). A non-digit ends the
//!    loop, except `e`/`E` with DIGITS_SEEN, which enters the exponent
//!    phase.
//! 6. Exponent: the `e` is consumed, DIGITS_SEEN and EXP_NEGATIVE are
//!    CLEARED, an optional `+`/`-` is consumed (`-` sets EXP_NEGATIVE),
//!    the sign byte heads the exponent buffer, then up to 8 exponent
//!    digits are collected (leading zeros collapse: a `0` in the first
//!    slot does not advance the write cursor). Exponent digits past the
//!    8-slot limit are consumed but saturate `frac_adjust` to +9999 /
//!    -9999 (constants DAT_08036774/DAT_08036778), guaranteeing the
//!    converter's ±500 range guard fires. With zero exponent digits
//!    DIGITS_SEEN stays clear, so `"1e"` is a matching failure (-2) —
//!    the bare `e` is NOT pushed back (only one ungetc exists).
//! 7. One `ungetc` pushes back the terminating char (harmless when it
//!    fails on the sticky-EOF path), both buffers are 0xff-terminated,
//!    and [`scanf_float_convert`] is called as
//!    `f(result, exp_buf, mant_buf, frac_adjust)`. No DIGITS_SEEN
//!    returns -2. Otherwise the double result is stored through the next
//!    `ap` slot (`ap` advances 4 bytes) when flags & 0x24 != 0 (the
//!    `l`/`L` size bits — `vsscanf` seeds flags = 4, so the strtod path
//!    is always double), or narrowed to a float and stored when clear.
//!    `*` suppression (flags & 1) skips the store. The consumed count is
//!    returned.
//!
//! `consumed_out` (r2) is written with the net consumed count at every
//! point a character is committed (digit, leading zero, post-dot zero,
//! exponent digit) and is NOT written on the failure paths — the strtod
//! wrapper `FUN_080331dc` aliases it onto the input state's `ap` field.
//!
//! Register usage of the original: r0 = unused (stored on the stack,
//! never read), r1 = `input` (full [`ScanfState`], the getc/ungetc
//! argument), r2 = `consumed_out` (`*mut i32`), r3 = `conv`
//! ([`ScanfConvState`]: ap @ 0, flags @ 4, width @ 8, getc @ 0x18,
//! ungetc @ 0x1c, ctype @ 0x20). Result in r0: consumed count >= 0, 0 on
//! EOF before the field, -2 on a matching failure (no digits). The Rust
//! signature keeps the four register-level parameters, so the function
//! is ABI-identical to the original and to the `ScanfEngineFn` hook
//! shape (four word-sized args; installable into `SCANF_ENGINE` with an
//! ABI-compatible cast).
//!
//! RetailOS stub findings (verified on the machine code):
//! - The inf/nan literal matcher (bl 0x083ed1c0 @ 0x08036454, dispatched
//!   from the `i`/`I`/`n`/`N` check @ 0x08036420) and the `0x` hex-float
//!   matcher (bl 0x083ed1bc @ 0x080364dc) are NULL VENEERS: both targets
//!   are a single `mov pc, lr`, so the calls return their r0 argument
//!   (-3 = "no literal") unchanged and the engine ALWAYS falls through
//!   to the decimal paths. `inf`/`nan` input is therefore a plain -2
//!   matching failure and `0x10` scans as `0.0` leaving `x10`. The
//!   dispatch sites are kept as comments. The original also maintained a
//!   leading-zero counter (sp+0x14) solely to gate the hex veneer (`0x`
//!   valid only after exactly one zero); with the veneer stubbed it has
//!   no observable effect and is not ported.
//! - The decimal point character is read from the ADS runtime locale:
//!   `FUN_0803204c` returns the locale block (in DRAM, runtime-
//!   initialized), and the engine loads `lc_numeric.decimal_point[0]`
//!   through it (0x08036374-0x08036384). The firmware never leaves the C
//!   locale, so the byte is always `'.'`; ported as the constant
//!   [`DECIMAL_POINT`].
//!
//! Simplifications / deviations vs. the original:
//! - The double -> float narrowing veneer `FUN_08036e4c` @ 0x08036e4c
//!   (itself a wrapper around the ADS checked narrower @ 0x08036d7c /
//!   `__d2f` @ 0x083eae74) routes through the [`SCANF_FLOAT_NARROW`]
//!   function pointer, mirroring the `SOFTFLOAT_OPS` pattern in
//!   scanf_float.rs. The default is the ported veneer
//!   (`scanf_narrow_float` in fp/d2f_checked.rs); host tests may swap in
//!   mocks. The double path (vsscanf/strtod) never touches it. Like
//!   the original, the narrow runs even when assignment is suppressed.
//! - The original keeps flags in r4 for the whole function (`bic r4, r4,
//!   #0x680` on entry clears NEGATIVE/DIGITS_SEEN/PAST_DOT) and never
//!   writes `conv.flags` back; neither does this port (only `conv.ap`
//!   changes).
//! - `conv.getc/ungetc/ctype` are `Option`s in the shared struct; the
//!   original blindly calls them, so this port uses `unwrap_unchecked`
//!   (same convention as scanf_int.rs).
//! - Stack buffers: mantissa is 20 bytes (sign @ [0], 18 digit slots,
//!   0xff terminator), exponent 10 bytes (sign @ [0], 8 digit slots,
//!   terminator) — the original's stack frame has more slack, but these
//!   are the exact extents the machine code can touch.

use crate::scanf_float::scanf_float_convert;
use crate::scanf_helpers::{ScanfConvState, ScanfState};
use core::ffi::c_void;

/// `*` — assignment suppression: consume and convert, but do not store.
const FLAG_SUPPRESS: u32 = 0x001;
/// Size-mask selecting the double store path (the `l`/`L` bits; vsscanf
/// seeds flags = 4, so the strtod path always stores a double). When
/// clear, the result is narrowed to float via [`SCANF_FLOAT_NARROW`].
const FLAG_DOUBLE_MASK: u32 = 0x024;
/// Internal (engine-local): the decimal point has been consumed.
const FLAG_PAST_DOT: u32 = 0x080;
/// Internal (engine-local): the exponent sign was `-`.
const FLAG_EXP_NEGATIVE: u32 = 0x100;
/// Internal (engine-local): at least one digit was consumed (leading
/// zeros and post-dot zeros count). Cleared on entry and NOT written
/// back to `conv.flags`.
const FLAG_DIGITS_SEEN: u32 = 0x200;
/// Internal (engine-local): a `-` sign was consumed.
const FLAG_NEGATIVE: u32 = 0x400;
/// Internal bits cleared on entry (the original's `bic r4, r4, #0x680`).
const FLAG_CLEAR_MASK: u32 = FLAG_NEGATIVE | FLAG_DIGITS_SEEN | FLAG_PAST_DOT;

/// Decimal point character. The original reads
/// `lc_numeric.decimal_point[0]` from the ADS runtime locale block via
/// `FUN_0803204c`; the firmware never leaves the C locale, where it is
/// `'.'` (see module docs).
const DECIMAL_POINT: i32 = b'.' as i32;

/// Mantissa buffer: sign byte + 18 digit slots + 0xff terminator
/// (original: sp+0x2c..sp+0x3f).
const MANT_BUF_LEN: usize = 20;
/// Exponent buffer: sign byte + 8 digit slots + 0xff terminator
/// (original: sp+0x20..sp+0x29).
const EXP_BUF_LEN: usize = 10;
/// First digit slot index in both buffers (slot 0 holds the sign byte).
const FIRST_DIGIT: usize = 1;

/// Saturating `frac_adjust` loaded when the exponent digit buffer
/// overflows (DAT_08036774 = 9999 / DAT_08036778 = -9999): forces the
/// converter's ±500 range guard, yielding +/-inf or +/-0 with ERANGE.
const EXP_OVERFLOW_POS: i32 = 9999;
const EXP_OVERFLOW_NEG: i32 = -9999;

/// Indirect dispatch for the double -> float narrowing veneer
/// `FUN_08036e4c` @ 0x08036e4c (ported as `scanf_narrow_float` in
/// fp/d2f_checked.rs, now the default). Signature mirrors the original:
/// r0 = out float word, r1 = in double (lo word first).
pub type ScanfFloatNarrowFn = unsafe extern "C" fn(out_float: *mut u32, in_double: *const u32);

/// The active double -> float narrowing implementation. Defaults to the
/// ported `FUN_08036e4c` veneer (`scanf_narrow_float`, which chains the
/// checked `d2f_errno` narrower); host tests may temporarily swap in
/// mocks. Written once (if at all) at init on target; tests serialize
/// access.
pub static mut SCANF_FLOAT_NARROW: ScanfFloatNarrowFn = crate::d2f_checked::scanf_narrow_float;

/// Reads the narrow op. Volatile for the same reason as scanf_float.rs's
/// `softfloat_ops()`: the pointer is meant to be swapped at runtime, and
/// in a build where nothing writes it yet LLVM would otherwise
/// constant-fold the load to the default stub and inline its `loop {}`.
#[inline(always)]
fn narrow_op() -> ScanfFloatNarrowFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCANF_FLOAT_NARROW)) }
}

/// `scanf_float_engine` — original: `FUN_08036348` @ 0x08036348
/// (1052 bytes).
///
/// See the module docs for the full algorithm, the buffer formats and
/// the retailOS stub findings. `unused_r0` mirrors the original's r0
/// (pushed on entry, never read). Returns the number of input characters
/// consumed (>= 0), 0 when EOF hit during the leading whitespace skip,
/// or -2 when no valid digits were present (matching failure — this
/// includes `inf`/`nan` input and bare `"1e"`, see module docs).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scanf_float_engine(
    unused_r0: i32,
    input: *mut ScanfState,
    consumed_out: *mut i32,
    conv: *mut ScanfConvState,
) -> i32 {
    let _ = unused_r0; // never read by the original
    let conv = &mut *conv;
    let getc = conv.getc.unwrap_unchecked();
    let ungetc = conv.ungetc.unwrap_unchecked();
    let ctype = conv.ctype.unwrap_unchecked();

    // The original keeps flags in r4 for the whole function and clears
    // the three internal bits up front; conv.flags is never written back.
    let mut flags = conv.flags & !FLAG_CLEAR_MASK;
    let mut width = conv.width;
    let mut consumed: i32 = -1;
    let mut frac_adjust: i32 = 0;

    let mut mant = [0u8; MANT_BUF_LEN];
    let mut exp = [0u8; EXP_BUF_LEN];

    // Skip leading whitespace (ctype(c) != 0), counting every char read
    // — including, like the original, the one that ends the loop.
    let mut c: i32;
    loop {
        consumed = consumed.wrapping_add(1);
        c = getc(input);
        if ctype(c) == 0 {
            break;
        }
    }
    // EOF before any non-space char: the machine code returns 0
    // (`mvneq r0, #0` @ 0x080363b8), NOT -1 as Ghidra shows.
    if c == -1 {
        return 0;
    }

    // Optional sign, only when width remains.
    if width > 0 && (c == b'+' as i32 || c == b'-' as i32) {
        if c == b'-' as i32 {
            flags |= FLAG_NEGATIVE;
        }
        consumed = consumed.wrapping_add(1);
        c = getc(input);
        width = width.wrapping_sub(1);
    }

    // Mantissa buffer heads with the ASCII sign byte; digits start at 1.
    // Buffer cursors are bounded by construction (mant_len <= 19,
    // exp_len <= 9 — the store paths stop at the limits), so all
    // indexing is unchecked: the original has no bounds checks either.
    *mant.get_unchecked_mut(0) = if flags & FLAG_NEGATIVE != 0 { b'-' } else { b'+' };
    let mut mant_len = FIRST_DIGIT;
    // Exponent cursor: still at the sign slot unless the exponent phase
    // runs, so the finish stores 0xff at [0] = "empty exponent".
    let mut exp_len = 0usize;

    if width > 0 {
        // inf/nan literal dispatch @ 0x08036420 ('i'/'I'/'n'/'N' ->
        // bl 0x083ed1c0): the veneer is a null `mov pc, lr` in retailOS
        // and always returns -3 ("no literal"), so the characters simply
        // fall through to the decimal paths below (a -2 failure).
        //
        // Leading zeros (consumed, not stored) and the `0x` hex dispatch
        // (bl 0x083ed1bc — likewise a null veneer, so `0x` is never
        // hex); the original's leading-zero counter existed only to gate
        // that stubbed call and is not ported.
        loop {
            if c != b'0' as i32 {
                break;
            }
            consumed = consumed.wrapping_add(1);
            c = getc(input);
            width = width.wrapping_sub(1);
            flags |= FLAG_DIGITS_SEEN;
            *consumed_out = consumed;
            if width <= 0 {
                break;
            }
        }
    }

    // A decimal point before the main loop (leading `.5`, or the char
    // after leading zeros/sign): zeros right after it are consumed
    // without being stored, each scaling the exponent down. There is NO
    // width guard on this block in the original.
    if c == DECIMAL_POINT {
        flags |= FLAG_PAST_DOT;
        loop {
            width = width.wrapping_sub(1);
            consumed = consumed.wrapping_add(1);
            c = getc(input);
            if c != b'0' as i32 {
                break;
            }
            frac_adjust = frac_adjust.wrapping_sub(1);
            flags |= FLAG_DIGITS_SEEN;
            *consumed_out = consumed.wrapping_add(1);
        }
    }

    // Main loop: digits into the mantissa buffer, one more decimal
    // point, then an optional exponent phase on `e`/`E`.
    'main: while width > 0 {
        if c == DECIMAL_POINT && flags & FLAG_PAST_DOT == 0 {
            flags |= FLAG_PAST_DOT;
            width = width.wrapping_sub(1);
        } else {
            let digit = (c as u32).wrapping_sub(b'0' as u32);
            if digit >= 10 {
                // Non-digit: an `e`/`E` with digits already seen enters
                // the exponent phase (the original's width re-check here
                // is unreachable — the loop guard already guarantees
                // width > 0); anything else ends the field.
                if width > 0
                    && (c == b'e' as i32 || c == b'E' as i32)
                    && flags & FLAG_DIGITS_SEEN != 0
                {
                    // The `e` resets the digits/exponent-sign bits: zero
                    // exponent digits makes the whole field a -2
                    // matching failure ("1e" rejection).
                    flags &= !(FLAG_DIGITS_SEEN | FLAG_EXP_NEGATIVE);
                    width = width.wrapping_sub(1);
                    consumed = consumed.wrapping_add(1);
                    c = getc(input);
                    // Optional exponent sign. With width exhausted the
                    // original substitutes a space placeholder (movle
                    // r1, #0x20), which matches neither branch — i.e.
                    // no sign is consumed.
                    if width > 0 {
                        if c == b'+' as i32 {
                            consumed = consumed.wrapping_add(1);
                            c = getc(input);
                            width = width.wrapping_sub(1);
                        } else if c == b'-' as i32 {
                            flags |= FLAG_EXP_NEGATIVE;
                            consumed = consumed.wrapping_add(1);
                            c = getc(input);
                            width = width.wrapping_sub(1);
                        }
                    }
                    *exp.get_unchecked_mut(0) =
                        if flags & FLAG_EXP_NEGATIVE != 0 { b'-' } else { b'+' };
                    exp_len = FIRST_DIGIT;
                    while width > 0 && (c as u32).wrapping_sub(b'0' as u32) < 10 {
                        flags |= FLAG_DIGITS_SEEN;
                        width = width.wrapping_sub(1);
                        if exp_len < EXP_BUF_LEN - 1 {
                            let d = (c as u32).wrapping_sub(b'0' as u32) as u8;
                            *exp.get_unchecked_mut(exp_len) = d;
                            // Leading zeros collapse: a 0 in the first
                            // digit slot does not advance the cursor
                            // (the terminator overwrites it).
                            if d != 0 || exp_len > FIRST_DIGIT {
                                exp_len += 1;
                            }
                        } else {
                            // Exponent buffer full: saturate so the
                            // converter's ±500 guard fires.
                            frac_adjust = if flags & FLAG_EXP_NEGATIVE != 0 {
                                EXP_OVERFLOW_NEG
                            } else {
                                EXP_OVERFLOW_POS
                            };
                        }
                        consumed = consumed.wrapping_add(1);
                        c = getc(input);
                        *consumed_out = consumed;
                    }
                }
                break 'main;
            }
            // Digit: set DIGITS_SEEN and charge width in both the store
            // and the overflow paths (the original does both before the
            // buffer-limit branch).
            flags |= FLAG_DIGITS_SEEN;
            width = width.wrapping_sub(1);
            if mant_len < MANT_BUF_LEN - 1 {
                if flags & FLAG_PAST_DOT != 0 {
                    frac_adjust = frac_adjust.wrapping_sub(1);
                }
                *mant.get_unchecked_mut(mant_len) = digit as u8;
                mant_len += 1;
            } else if flags & FLAG_PAST_DOT == 0 {
                // Integer digit past the 18-slot limit: dropped, but the
                // value keeps its magnitude via the exponent.
                frac_adjust = frac_adjust.wrapping_add(1);
            }
        }
        // Consume tail: commit the char (consumed_out only once digits
        // were seen), then read the next one.
        if flags & FLAG_DIGITS_SEEN != 0 {
            *consumed_out = consumed.wrapping_add(1);
        }
        consumed = consumed.wrapping_add(1);
        c = getc(input);
    }

    // Push back the terminating char (harmless when it fails on the
    // sticky-EOF path; the result is discarded in the original too).
    ungetc(input);
    *mant.get_unchecked_mut(mant_len) = 0xff;
    *exp.get_unchecked_mut(exp_len) = 0xff;

    let mut result = [0u32; 2];
    scanf_float_convert(result.as_mut_ptr(), exp.as_ptr(), mant.as_ptr(), frac_adjust);

    if flags & FLAG_DIGITS_SEEN == 0 {
        return -2;
    }
    if flags & FLAG_DOUBLE_MASK != 0 {
        if flags & FLAG_SUPPRESS == 0 {
            let slot = conv.ap as *mut *mut u32;
            let dest = slot.read();
            conv.ap = slot.add(1) as *mut c_void;
            dest.write(result[0]);
            dest.add(1).write(result[1]);
        }
        return consumed;
    }
    // Float store: the original narrows BEFORE testing suppression (the
    // real narrow sets errno on range even for a suppressed store).
    let mut float_word = [0u32; 1];
    narrow_op()(float_word.as_mut_ptr(), result.as_ptr());
    if flags & FLAG_SUPPRESS == 0 {
        let slot = conv.ap as *mut *mut u32;
        let dest = slot.read();
        conv.ap = slot.add(1) as *mut c_void;
        dest.write(float_word[0]);
    }
    consumed
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::scanf_float::{SoftfloatOps, SOFTFLOAT_OPS};
    use crate::scanf_helpers::{string_getc, string_ungetc};
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap SOFTFLOAT_OPS / SCANF_FLOAT_NARROW.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    // ---- Host f64 mock of the soft-float primitives ----
    //
    // Same construction as scanf_float.rs's committed tests: the
    // extended format is value = M * 2^(field - 0x40000000 - 62) with M
    // the 64-bit hi:lo mantissa (top bit set). Result bits are identical
    // under either module's mock, so a same-math table swap mid-test
    // cannot corrupt the value assertions here.

    fn ext_from_f64(d: f64) -> [u32; 3] {
        if d == 0.0 {
            return [0x4000_0000, 0, 0];
        }
        let bits = d.abs().to_bits();
        let exp_bits = ((bits >> 52) & 0x7ff) as i64;
        let mant53 = (bits & 0x000f_ffff_ffff_ffff) | 0x0010_0000_0000_0000;
        let m64 = mant53 << 11;
        let field = (0x4000_0000i64 + exp_bits - 1024) as u32;
        [field, (m64 >> 32) as u32, m64 as u32]
    }

    fn ext_to_f64(e: [u32; 3]) -> f64 {
        let m = ((e[1] as u64) << 32) | e[2] as u64;
        (m as f64) * 2f64.powi(e[0] as i32 - 0x4000_0000 - 62)
    }

    static mut ERRNO_VALUES: Vec<i32> = Vec::new();

    unsafe extern "C" fn mock_pow10(out: *mut u32, exp: u32, _adj: i32) {
        let e = ext_from_f64(10f64.powi(exp as i32));
        core::ptr::copy_nonoverlapping(e.as_ptr(), out, 3);
    }

    unsafe extern "C" fn mock_ext_mul(a: *const u32, b: *const u32, _adj: i32) -> u64 {
        let ea = [a.read(), a.add(1).read(), a.add(2).read()];
        let eb = [b.read(), b.add(1).read(), b.add(2).read()];
        (ext_to_f64(ea) * ext_to_f64(eb)).to_bits()
    }

    unsafe extern "C" fn mock_ext_div(a: *const u32, b: *const u32, _adj: i32) -> u64 {
        let ea = [a.read(), a.add(1).read(), a.add(2).read()];
        let eb = [b.read(), b.add(1).read(), b.add(2).read()];
        (ext_to_f64(ea) / ext_to_f64(eb)).to_bits()
    }

    unsafe extern "C" fn mock_set_errno(value: i32) {
        (*core::ptr::addr_of_mut!(ERRNO_VALUES)).push(value);
    }

    const MOCK_OPS: SoftfloatOps = SoftfloatOps {
        pow10: mock_pow10,
        ext_mul: mock_ext_mul,
        ext_div: mock_ext_div,
        set_errno: mock_set_errno,
    };

    /// Host double -> float narrowing mock (FUN_08036e4c stand-in):
    /// plain `as f32` truncation-oracle is enough for plumbing tests; the
    /// engine only forwards bits.
    static mut NARROW_CALLS: usize = 0;

    unsafe extern "C" fn mock_narrow(out_float: *mut u32, in_double: *const u32) {
        *core::ptr::addr_of_mut!(NARROW_CALLS) += 1;
        let bits = ((in_double.add(1).read() as u64) << 32) | in_double.read() as u64;
        out_float.write((f64::from_bits(bits) as f32).to_bits());
    }

    /// ADS ctype whitespace test (bit 0): space, \t, \n, \v, \f, \r.
    /// EOF (-1) is not whitespace, like the original's table lookup
    /// clamping to 0.
    unsafe extern "C" fn ctype_isspace(c: i32) -> i32 {
        match c {
            0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d => 1,
            _ => 0,
        }
    }

    /// Installs the mock tables, returns the lock guard. The narrow mock
    /// is installed too; tests that care reset NARROW_CALLS themselves.
    fn mock_ops() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(ERRNO_VALUES)).clear();
            *core::ptr::addr_of_mut!(NARROW_CALLS) = 0;
            *core::ptr::addr_of_mut!(SOFTFLOAT_OPS) = MOCK_OPS;
            *core::ptr::addr_of_mut!(SCANF_FLOAT_NARROW) = mock_narrow;
        }
        guard
    }

    const SENTINEL: u32 = 0xdead_beef;
    const CONSUMED_SENTINEL: i32 = -777;

    /// One va_list slot: 4 bytes on the ARM target, 8 on 64-bit hosts.
    const AP_SLOT: usize = core::mem::size_of::<*mut u32>();

    /// Outcome of one engine run.
    struct Scan {
        ret: i32,
        consumed_out: i32,
        /// Destination double slot (two words).
        dst: [u32; 2],
        /// Bytes the input cursor advanced (net consumed by the stream).
        stream_pos: usize,
        errno: Vec<i32>,
        /// Bytes conv.ap advanced (0 or one 4-byte slot).
        ap_advance: usize,
    }

    /// Runs the engine over a byte string (a NUL is appended) with the
    /// real scanf_float_convert behind it. `flags` is the conv flag word
    /// (vsscanf seeds 4 = double store; add 1 for `*` suppression).
    unsafe fn run(input: &[u8], width: i32, flags: u32) -> Scan {
        (*core::ptr::addr_of_mut!(ERRNO_VALUES)).clear();
        let mut buf = input.to_vec();
        buf.push(0);
        let mut state = ScanfState {
            ptr: buf.as_ptr(),
            count: -1,
            base: buf.as_ptr(),
            eof: 0,
            ap: core::ptr::null_mut(),
            flags: 0,
            width: 0,
            fmt_cursor: core::ptr::null(),
            scanset_flag: 0,
            fmt_getc: None,
            getc: None,
            ungetc: None,
            ctype: None,
        };
        let mut dst = [SENTINEL; 2];
        let mut slot: *mut u32 = dst.as_mut_ptr();
        let ap_base = &mut slot as *mut *mut u32;
        let mut conv = ScanfConvState {
            ap: ap_base as *mut c_void,
            flags,
            width,
            fmt_cursor: core::ptr::null(),
            scanset_flag: 0,
            fmt_getc: None,
            getc: Some(string_getc),
            ungetc: Some(string_ungetc),
            ctype: Some(ctype_isspace),
        };
        let mut consumed_out = CONSUMED_SENTINEL;
        let ret = scanf_float_engine(0, &mut state, &mut consumed_out, &mut conv);
        Scan {
            ret,
            consumed_out,
            dst,
            stream_pos: state.ptr as usize - buf.as_ptr() as usize,
            errno: (*core::ptr::addr_of!(ERRNO_VALUES)).clone(),
            ap_advance: conv.ap as usize - ap_base as usize,
        }
    }

    /// Convenience: default double-store flags (what vsscanf seeds).
    unsafe fn scan(input: &[u8]) -> Scan {
        run(input, i32::MAX, 4)
    }

    fn dst_bits(s: &Scan) -> u64 {
        ((s.dst[1] as u64) << 32) | s.dst[0] as u64
    }

    /// Two-step expectation mirroring the mock (64-bit mantissa rounded
    /// to f64, then correctly-rounded multiply/divide by 10^|exp|) —
    /// identical to a host parse for correctly-rounded cases, but robust
    /// for the long-mantissa vectors.
    fn two_step(negative: bool, mantissa: u64, exp: i32) -> u64 {
        let v = if exp >= 1 {
            mantissa as f64 * 10f64.powi(exp)
        } else {
            mantissa as f64 / 10f64.powi(-exp)
        };
        if negative {
            (-v).to_bits()
        } else {
            v.to_bits()
        }
    }

    #[test]
    fn plain_decimal_3_14() {
        let _lock = mock_ops();
        unsafe {
            let s = scan(b"3.14");
            assert_eq!(s.ret, 4);
            assert_eq!(s.consumed_out, 4);
            assert_eq!(s.stream_pos, 4);
            assert_eq!(dst_bits(&s), 3.14f64.to_bits());
            assert!(s.errno.is_empty());
            assert_eq!(s.ap_advance, AP_SLOT);
        }
    }

    #[test]
    fn negative_with_exponent() {
        let _lock = mock_ops();
        unsafe {
            let s = scan(b"-1.5e3");
            assert_eq!(s.ret, 6);
            assert_eq!(s.consumed_out, 6);
            assert_eq!(dst_bits(&s), (-1500.0f64).to_bits());
            assert!(s.errno.is_empty());
        }
    }

    #[test]
    fn negative_exponent() {
        let _lock = mock_ops();
        unsafe {
            let s = scan(b"1e-2");
            assert_eq!(s.ret, 4);
            assert_eq!(s.consumed_out, 4);
            assert_eq!(dst_bits(&s), 0.01f64.to_bits());
        }
    }

    #[test]
    fn explicit_positive_exponent_sign() {
        let _lock = mock_ops();
        unsafe {
            let s = scan(b"1e+5");
            assert_eq!(s.ret, 4);
            assert_eq!(dst_bits(&s), 100000.0f64.to_bits());
        }
    }

    #[test]
    fn leading_dot() {
        let _lock = mock_ops();
        unsafe {
            let s = scan(b".5");
            assert_eq!(s.ret, 2);
            assert_eq!(s.consumed_out, 2);
            assert_eq!(dst_bits(&s), 0.5f64.to_bits());
        }
    }

    #[test]
    fn trailing_dot() {
        let _lock = mock_ops();
        unsafe {
            let s = scan(b"5.");
            assert_eq!(s.ret, 2);
            assert_eq!(s.consumed_out, 2);
            assert_eq!(dst_bits(&s), 5.0f64.to_bits());
            // EOF right after the dot is fine too.
            let s = scan(b"3.");
            assert_eq!(s.ret, 2);
            assert_eq!(dst_bits(&s), 3.0f64.to_bits());
        }
    }

    #[test]
    fn bare_exponent_marker_is_rejected() {
        let _lock = mock_ops();
        unsafe {
            // "1e": the `e` clears DIGITS_SEEN and no exponent digit
            // re-sets it -> -2. The `e` is consumed and NOT pushed back.
            let s = scan(b"1e");
            assert_eq!(s.ret, -2);
            assert_eq!(s.consumed_out, 1, "last commit was the digit");
            assert_eq!(s.stream_pos, 2, "the bare e stays consumed at EOF");
            assert_eq!(s.dst, [SENTINEL; 2], "no store on failure");
            assert_eq!(s.ap_advance, 0);
            // "1ex": the x is pushed back, the e is not.
            let s = scan(b"1ex");
            assert_eq!(s.ret, -2);
            assert_eq!(s.consumed_out, 1);
            assert_eq!(s.stream_pos, 2);
            // "1e+" / "1e-": sign consumed, still no digits -> -2.
            for input in [&b"1e+"[..], &b"1e-"[..]] {
                let s = scan(input);
                assert_eq!(s.ret, -2, "input {input:?}");
                assert_eq!(s.consumed_out, 1);
                assert_eq!(s.dst, [SENTINEL; 2]);
            }
            // Width exhausted right after the `e` (the original's space
            // placeholder path): no sign, no digits -> -2.
            let s = run(b"1e5", 2, 4);
            assert_eq!(s.ret, -2);
            assert_eq!(s.stream_pos, 2, "the 5 is pushed back");
        }
    }

    #[test]
    fn inf_and_nan_literals_are_never_matched() {
        let _lock = mock_ops();
        unsafe {
            // The literal matcher is a null veneer in retailOS, so every
            // inf/nan variant is a plain -2 matching failure and the
            // first char is pushed back.
            for input in [
                &b"inf"[..],
                &b"INF"[..],
                &b"Inf"[..],
                &b"infinity"[..],
                &b"nan"[..],
                &b"NAN"[..],
                &b"NaN"[..],
                &b"-inf"[..],
                &b"+nan"[..],
            ] {
                let s = scan(input);
                assert_eq!(s.ret, -2, "input {input:?}");
                assert_eq!(s.consumed_out, CONSUMED_SENTINEL, "no commit for {input:?}");
                assert_eq!(s.dst, [SENTINEL; 2]);
                let expect = if input[0] == b'-' || input[0] == b'+' { 1 } else { 0 };
                assert_eq!(s.stream_pos, expect, "only the sign stays consumed for {input:?}");
            }
        }
    }

    #[test]
    fn hex_float_prefix_is_never_matched() {
        let _lock = mock_ops();
        unsafe {
            // The 0x veneer is a null stub: "0x10" scans as 0.0 and the
            // x is pushed back.
            let s = scan(b"0x10");
            assert_eq!(s.ret, 1);
            assert_eq!(s.consumed_out, 1);
            assert_eq!(s.stream_pos, 1);
            assert_eq!(dst_bits(&s), 0.0f64.to_bits());
        }
    }

    #[test]
    fn width_limits_truncate_collection() {
        let _lock = mock_ops();
        unsafe {
            // %3f of "3.14159": "3.1" — the 4 is pushed back.
            let s = run(b"3.14159", 3, 4);
            assert_eq!(s.ret, 3);
            assert_eq!(s.consumed_out, 3);
            assert_eq!(s.stream_pos, 3);
            assert_eq!(dst_bits(&s), 3.1f64.to_bits());
            // Width 1: just the integer digit.
            let s = run(b"3.14", 1, 4);
            assert_eq!(s.ret, 1);
            assert_eq!(dst_bits(&s), 3.0f64.to_bits());
            // Width 2 with a sign.
            let s = run(b"-1.5", 2, 4);
            assert_eq!(s.ret, 2);
            assert_eq!(dst_bits(&s), (-1.0f64).to_bits());
            // Width cutting the exponent: "1e" path -> -2 (see above);
            // width 3 keeps one exponent digit.
            let s = run(b"1e25", 3, 4);
            assert_eq!(s.ret, 3);
            assert_eq!(dst_bits(&s), 100.0f64.to_bits());
        }
    }

    #[test]
    fn suppressed_assignment_consumes_but_does_not_store() {
        let _lock = mock_ops();
        unsafe {
            // flags 1 = `*`: double-size suppressed.
            let s = run(b"2.5", i32::MAX, 4 | 1);
            assert_eq!(s.ret, 3);
            assert_eq!(s.consumed_out, 3);
            assert_eq!(s.dst, [SENTINEL; 2]);
            assert_eq!(s.ap_advance, 0, "suppression does not touch ap");
            // Suppression on the FLOAT path still runs the narrow (the
            // original narrows before testing the suppress bit).
            let s = run(b"2.5", i32::MAX, 1);
            assert_eq!(s.ret, 3);
            assert_eq!(core::ptr::addr_of!(NARROW_CALLS).read(), 1);
            assert_eq!(s.dst, [SENTINEL; 2]);
        }
    }

    #[test]
    fn eof_handling() {
        let _lock = mock_ops();
        unsafe {
            // Empty / whitespace-only input: the original returns 0
            // (mvneq r0, #0), not -1.
            let s = scan(b"");
            assert_eq!(s.ret, 0);
            assert_eq!(s.stream_pos, 0);
            let s = scan(b" \t\n ");
            assert_eq!(s.ret, 0);
            assert_eq!(s.stream_pos, 4);
            // Leading whitespace counts toward the consumed total.
            let s = scan(b"  5");
            assert_eq!(s.ret, 3);
            assert_eq!(s.consumed_out, 3);
            assert_eq!(dst_bits(&s), 5.0f64.to_bits());
            // EOF terminates the field mid-token: "2.5" then NUL.
            let s = scan(b"2.5");
            assert_eq!(s.ret, 3);
            assert_eq!(dst_bits(&s), 2.5f64.to_bits());
        }
    }

    #[test]
    fn zeros_and_signs() {
        let _lock = mock_ops();
        unsafe {
            // A lone zero scans as 0.0 (never enters the buffer).
            let s = scan(b"0");
            assert_eq!(s.ret, 1);
            assert_eq!(dst_bits(&s), 0.0f64.to_bits());
            // Negative zero: the sign byte makes the converter produce
            // -0.0 even with an empty mantissa.
            let s = scan(b"-0");
            assert_eq!(s.ret, 2);
            assert_eq!(dst_bits(&s), (-0.0f64).to_bits());
            // Leading zeros then digits.
            let s = scan(b"007");
            assert_eq!(s.ret, 3);
            assert_eq!(dst_bits(&s), 7.0f64.to_bits());
            // Post-dot zeros scale the exponent without being stored.
            let s = scan(b"0.0005");
            assert_eq!(s.ret, 6);
            assert_eq!(dst_bits(&s), 0.0005f64.to_bits());
            let s = scan(b".05");
            assert_eq!(s.ret, 3);
            assert_eq!(dst_bits(&s), 0.05f64.to_bits());
            // Signed fraction without integer part.
            let s = scan(b"+.5");
            assert_eq!(s.ret, 3);
            assert_eq!(dst_bits(&s), 0.5f64.to_bits());
            let s = scan(b"-.5");
            assert_eq!(s.ret, 3);
            assert_eq!(dst_bits(&s), (-0.5f64).to_bits());
            // 0.0 with a trailing junk char: junk pushed back.
            let s = scan(b"0.0x");
            assert_eq!(s.ret, 3);
            assert_eq!(s.stream_pos, 3);
            assert_eq!(dst_bits(&s), 0.0f64.to_bits());
        }
    }

    #[test]
    fn no_digits_is_matching_failure() {
        let _lock = mock_ops();
        unsafe {
            for input in [&b"x"[..], &b"."[..], &b"+"[..], &b"-"[..], &b"+."[..], &b"e5"[..]] {
                let s = scan(input);
                assert_eq!(s.ret, -2, "input {input:?}");
                assert_eq!(s.dst, [SENTINEL; 2]);
            }
            // "." consumes the dot (PAST_DOT commits it) before failing.
            let s = scan(b".");
            assert_eq!(s.stream_pos, 1);
            // "x" is pushed back entirely.
            let s = scan(b"x");
            assert_eq!(s.stream_pos, 0);
        }
    }

    #[test]
    fn mantissa_overflow_keeps_magnitude() {
        let _lock = mock_ops();
        unsafe {
            // 22 integer digits: first 18 stored, remaining 4 dropped
            // with frac_adjust += 1 each -> mantissa * 10^4.
            let s = scan(b"1234567890123456789012");
            assert_eq!(s.ret, 22);
            assert_eq!(s.consumed_out, 22);
            assert_eq!(dst_bits(&s), two_step(false, 123456789012345678, 4));
            // Fraction digits past the limit are dropped silently
            // (frac_adjust untouched after the dot).
            let s = scan(b"0.1234567890123456789012");
            assert_eq!(s.ret, 24);
            assert_eq!(dst_bits(&s), two_step(false, 123456789012345678, -18));
        }
    }

    #[test]
    fn exponent_buffer_overflow_saturates() {
        let _lock = mock_ops();
        unsafe {
            // 9 exponent digits > 8 slots: frac_adjust saturates to
            // +9999, and the parsed exponent (first 8 digits) + 9999
            // blows the +500 guard -> +inf with ERANGE.
            let s = scan(b"1e123456789");
            assert_eq!(s.ret, 11);
            assert_eq!(dst_bits(&s), f64::INFINITY.to_bits());
            assert_eq!(s.errno, std::vec![2]);
            // Negative exponent overflow -> +0 with ERANGE.
            let s = scan(b"1e-123456789");
            assert_eq!(s.ret, 12);
            assert_eq!(dst_bits(&s), 0.0f64.to_bits());
            assert_eq!(s.errno, std::vec![2]);
        }
    }

    #[test]
    fn range_errors_from_the_converter() {
        let _lock = mock_ops();
        unsafe {
            let s = scan(b"1e999");
            assert_eq!(s.ret, 5);
            assert_eq!(dst_bits(&s), f64::INFINITY.to_bits());
            assert_eq!(s.errno, std::vec![2]);
            let s = scan(b"-1e999");
            assert_eq!(dst_bits(&s), f64::NEG_INFINITY.to_bits());
            assert_eq!(s.errno, std::vec![2]);
            let s = scan(b"1e-999");
            assert_eq!(dst_bits(&s), 0.0f64.to_bits());
            assert_eq!(s.errno, std::vec![2]);
            // Leading zeros in the exponent collapse: "1e002" is 100.0,
            // and "1e0" parses as an EMPTY exponent (0 overwrites the
            // first slot, the terminator replaces it).
            let s = scan(b"1e002");
            assert_eq!(dst_bits(&s), 100.0f64.to_bits());
            let s = scan(b"1e0");
            assert_eq!(s.ret, 3);
            assert_eq!(dst_bits(&s), 1.0f64.to_bits());
        }
    }

    #[test]
    fn float_store_path_uses_the_narrow_op() {
        let _lock = mock_ops();
        unsafe {
            // flags without the 0x24 double bits: single-precision store
            // through SCANF_FLOAT_NARROW (FUN_08036e4c stand-in).
            let s = run(b"2.5", i32::MAX, 0);
            assert_eq!(s.ret, 3);
            assert_eq!(core::ptr::addr_of!(NARROW_CALLS).read(), 1);
            assert_eq!(s.dst[0], 2.5f32.to_bits());
            assert_eq!(s.dst[1], SENTINEL, "float path stores one word");
            assert_eq!(s.ap_advance, AP_SLOT);
        }
    }

    #[test]
    fn engine_is_scanf_engine_hook_compatible() {
        let _lock = mock_ops();
        unsafe {
            use crate::scanf_helpers::{ScanfEngineFn, SCANF_ENGINE};
            // The four-word AAPCS contract matches ScanfEngineFn;
            // vsscanf calls engine(0, input, consumed_out, &conv).
            let typed: unsafe extern "C" fn(
                i32,
                *mut ScanfState,
                *mut i32,
                *mut ScanfConvState,
            ) -> i32 = scanf_float_engine;
            let engine: ScanfEngineFn = core::mem::transmute(typed);
            let saved = SCANF_ENGINE;
            SCANF_ENGINE = engine;
            let buf = b"7.25\0".to_vec();
            let mut state = ScanfState {
                ptr: buf.as_ptr(),
                count: -1,
                base: buf.as_ptr(),
                eof: 0,
                ap: core::ptr::null_mut(),
                flags: 0,
                width: 0,
                fmt_cursor: core::ptr::null(),
                scanset_flag: 0,
                fmt_getc: None,
                getc: None,
                ungetc: None,
                ctype: None,
            };
            let mut dst = [0u32; 2];
            let mut slot: *mut u32 = dst.as_mut_ptr();
            let mut conv = ScanfConvState {
                ap: &mut slot as *mut *mut u32 as *mut c_void,
                flags: 4,
                width: i32::MAX,
                fmt_cursor: core::ptr::null(),
                scanset_flag: 0,
                fmt_getc: None,
                getc: Some(string_getc),
                ungetc: Some(string_ungetc),
                ctype: Some(ctype_isspace),
            };
            let mut consumed = 0i32;
            let ret = SCANF_ENGINE(
                0,
                &mut state as *mut _ as usize,
                &mut consumed as *mut _ as usize,
                &mut conv as *mut _ as usize,
            );
            SCANF_ENGINE = saved;
            assert_eq!(ret, 4);
            assert_eq!(consumed, 4);
            assert_eq!(
                ((dst[1] as u64) << 32) | dst[0] as u64,
                7.25f64.to_bits()
            );
        }
    }
}

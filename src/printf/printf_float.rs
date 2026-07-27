//! printf float cluster (ARM ADS 1.0.1): the `%e/%E/%f/%F/%g/%G` wrapper
//! and the floating-point formatter behind it. Soft-float target: the
//! double travels as a u64 bit pattern and all classification is integer
//! bit manipulation — no f32/f64 arithmetic anywhere in module code.
//!
//! Ports:
//! - `convert_fe`   @ 0x08032d70 (420 bytes) — the wrapper the printf core
//!   calls for every float conversion. Sets the marker counters
//!   (state+0x0c/state+0x10) to -1, defaults the precision to 6 when no
//!   `.` was given, calls [`format_float`] into a 32-byte stack buffer,
//!   then emits: space padding (right-justified, no `0` flag), the sign
//!   prefix, zero padding, then the buffer — expanding the `'<'`/`'>'`
//!   markers into zero runs of state+0x0c/state+0x10 — then trailing
//!   spaces for `-`.
//! - `format_float` @ 0x0803285c (1264 bytes) — the formatter. Reads the
//!   locale decimal point (see [`DECIMAL_POINT`]), classifies the value
//!   (sign, inf, nan), picks the prefix string ("-"/"+"/" "/""), emits
//!   "inf"/"INF"/"nan"/"NAN" for non-finite values (clearing the `0`
//!   flag), and otherwise lays out digits from the dtoa back-end with
//!   `%e`/`%f`/`%g` style selection, precision clamping, `%g` trailing-zero
//!   stripping and the `'<'`/`'>'` deferred-zero markers.
//!
//! ABI (recovered from the call site @ 0x08034798 in the original core,
//! NOT the obvious guess): the core fetches the double as an 8-aligned
//! lo/hi pair into a stack slot and calls the wrapper as
//! `(state, spec, bits_ptr)` — r1 is the conversion character, r2 a
//! POINTER to the 8 value bytes. That is exactly the committed
//! `printf_core::FloatConverterFn` hook signature; `convert_fe` is that
//! hook's shipped default. One wrapper serves all of
//! %e/%E/%f/%F/%g/%G (the %a/%A veneer @ 0x083ed07c is a dead
//! `mov pc, lr` in this build), so there are no per-spec variants.
//!
//! Internal helpers folded in (only ever called from this cluster):
//! - `classify_double` — FUN_08035994 @ 0x08035994 + the `_fpclassify`
//!   primitive FUN_08036d0c @ 0x08036d0c. The primitive's classes are
//!   0=zero, 4=subnormal, 5=normal, 3=inf, 7=nan; the wrapper maps 3->2,
//!   7->1, else 0 and extracts the sign bit. Both fold into one exact
//!   IEEE bit test: exponent all-ones with zero/nonzero mantissa.
//! - `format_exponent` — FUN_080327e8 @ 0x080327e8 (116 bytes): appends
//!   `e<+|->NN` (three digits when the exponent exceeds 99) and returns
//!   the new length. 32-bit division only (committed rt_div).
//!
//! dtoa back-end (FUN_08032514 @ 0x08032514, ported concurrently in
//! printf_float_dtoa.rs) is reached through the [`DTOA`] fn-pointer hook
//! (SCANF_ENGINE pattern). Contract, from the call sites here:
//! `dtoa(out, digits, bits, ndigits, style)` writes `ndigits`-ish digit
//! characters plus NUL to `digits`, `out[0]` = decimal exponent E such
//! that value ~= D0.D1D2... * 10^E, `out[1]` = number of digit chars
//! written, `out[2]` = echo of `style` (written by the original, never
//! read here). style 1 (`%f`): digits of the value rounded to `ndigits`
//! fractional digits, fraction-exhaustion trimmed, 17 significant digits
//! max. style 0 (`%e`/`%g`): exactly `ndigits` significant digits.
//! The default stub ([`dtoa_not_ported`]) fabricates the +0.0 result so
//! output is benign until the real back-end lands.
//!
//! Simplifications / deviations vs. the original:
//! - The decimal point is read through the [`DECIMAL_POINT`] hook. The
//!   original reads the LC_NUMERIC block pointer from libspace+0x2c and
//!   treats the block's first word as the offset of the decimal_point
//!   string inside the block (`ldr r0,[blk]; ldrb dec,[blk,r0]`; the C
//!   block at 0x08986254 = {0xc, 0xe, 0xf, "."}). The committed libspace
//!   model stores that pointer as a raw u32 address word, which a 64-bit
//!   test host cannot dereference, so the read routes through the hook;
//!   the default [`decimal_point_from_libspace`] performs the original
//!   two-level read verbatim (valid on target once startup —
//!   FUN_08035788 — has installed the C-locale blocks, exactly like the
//!   original's dependency on that init).
//! - The 32-digit scratch buffer is zero-initialized; the original leaves
//!   stack garbage in it. Two shift loops in the original copy one byte
//!   past the dtoa NUL (i.e. garbage) into the buffer, but the returned
//!   length always excludes those bytes, so they are never emitted —
//!   zero-init only changes the value of unobservable bytes.
//! - Ghidra shows putc calls through `fn_ptr & 0xfffffffc` (Thumb-bit
//!   clear); the firmware is pure ARM, so the mask is omitted.
//! - Rounding correctness of the digits is the dtoa back-end's business;
//!   host tests mock it with host f64 formatting (std), so last-ulp
//!   rounding differences vs. ADS are possible there.

use crate::printf_helpers::{
    pad_emit, pad_emit_zero, PrintfState, FLAG_PRECISION_GIVEN, FLAG_ZERO_PAD,
};

/// Format flag: `+` — always show a sign (same bit as printf_core's
/// private FLAG_SHOW_SIGN; re-declared here since it is not shared).
pub const FLAG_SHOW_SIGN: u32 = 0x002;
/// Format flag: ` ` — space in front of non-negative numbers.
pub const FLAG_SPACE_SIGN: u32 = 0x004;
/// Format flag: `#` — alternate form (keep the decimal point / zeros).
pub const FLAG_ALT_FORM: u32 = 0x008;

/// Buffer marker: expand to `state+0x0c` zeros at emit time (deferred
/// integer zero run, e.g. the "00" in "0.001").
const INT_ZEROS_MARK: u8 = b'<';
/// Buffer marker: expand to `state+0x10` zeros at emit time (deferred
/// fraction zero run, e.g. precision digits past 17 significant digits).
const FRAC_ZEROS_MARK: u8 = b'>';

/// Largest significant-digit count the dtoa back-end produces; precisions
/// past this are satisfied with deferred zero runs.
const MAX_DIGITS: i32 = 17;

/// state+0x0c: pending integer zero run for the `'<'` marker
/// (`reserved_0c[0]`; the field is shared scratch owned by this cluster).
#[inline(always)]
unsafe fn int_zeros(state: *mut PrintfState) -> &'static mut i32 {
    &mut (*state).reserved_0c[0]
}

/// state+0x10: pending fraction zero run for the `'>'` marker
/// (`reserved_0c[1]`).
#[inline(always)]
unsafe fn frac_extra(state: *mut PrintfState) -> &'static mut i32 {
    &mut (*state).reserved_0c[1]
}

/// dtoa back-end signature (original: FUN_08032514 @ 0x08032514, called
/// with the style flag as a fifth, stack-passed argument). See the module
/// docs for the out/digits contract.
pub type DtoaFn =
    unsafe extern "C" fn(out: *mut i32, digits: *mut u8, bits: *const u64, ndigits: i32, style: i32);

/// Default [`DTOA`]: documented stub standing in for the dtoa back-end
/// (FUN_08032514, ported concurrently). Fabricates the +0.0 result:
/// style 1 yields no digits and exponent `-(ndigits + 1)`, style 0 yields
/// `ndigits` '0' digits and exponent 0 — every float conversion then
/// prints as zero ("0.000000", "0.000000e+00", "0") instead of hanging.
/// Replace with the real back-end before trusting finite float output.
unsafe extern "C" fn dtoa_not_ported(
    out: *mut i32,
    digits: *mut u8,
    _bits: *const u64,
    ndigits: i32,
    style: i32,
) {
    if style == 1 {
        *out = -(ndigits + 1);
        *out.add(1) = 0;
        *digits = 0;
    } else {
        let mut i = 0;
        while i < ndigits {
            *digits.add(i as usize) = b'0';
            i += 1;
        }
        *digits.add(ndigits as usize) = 0;
        *out = 0;
        *out.add(1) = ndigits;
    }
    *out.add(2) = style;
}

/// Installed dtoa back-end; see [`DtoaFn`]. Defaults to
/// [`dtoa_not_ported`]; swapped by host tests and by the real port in
/// printf_float_dtoa.rs.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut DTOA: DtoaFn = dtoa_not_ported;

/// Load the installed dtoa back-end. Volatile: with a single codegen
/// unit LLVM otherwise constant-folds the static to its initializer and
/// a runtime-installed back-end would never be called (same trick as
/// printf_core's float_converter).
#[inline(always)]
unsafe fn dtoa() -> DtoaFn {
    core::ptr::read_volatile(core::ptr::addr_of!(DTOA))
}

/// Locale decimal-point accessor. The default performs the original's
/// read; host tests swap in a fixed character (see module docs for why
/// the indirection exists).
pub type DecimalPointFn = unsafe extern "C" fn() -> u8;

/// Default [`DECIMAL_POINT`]: the original's two-level locale read —
/// the LC_NUMERIC block pointer at libspace+0x2c, whose first word is the
/// offset of the decimal_point string within the block
/// (original: `bl __rt_libspace; ldr r0,[r0,#0x2c]; ldr r1,[r0];
/// ldrb dec,[r0,r1]`). On target the block is installed by startup
/// (FUN_08035788 stores the C-locale block 0x08986254 there); before
/// that, like the original, this dereferences whatever the slot holds.
/// The libspace+0x2c word is modeled by runtime/locale.rs's LC_SLOTS
/// (the u32 slots in `Libspace` cannot hold host pointers), so the read
/// goes through its accessor — setlocale_core installs what this reads.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn decimal_point_from_libspace() -> u8 {
    let block = crate::runtime::locale::installed_lc_numeric_block();
    *block.add(*(block as *const u32) as usize)
}

/// Installed decimal-point accessor; see [`DecimalPointFn`].
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut DECIMAL_POINT: DecimalPointFn = decimal_point_from_libspace;

/// Load the installed decimal-point accessor (volatile — see [`dtoa`]).
#[inline(always)]
unsafe fn decimal_point() -> u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(DECIMAL_POINT))()
}

/// FUN_08035994 @ 0x08035994 + FUN_08036d0c @ 0x08036d0c folded into one
/// bit test (see module docs). Writes the sign bit (1 = negative) to
/// `sign_out`; returns 0 = finite, 1 = nan, 2 = inf.
unsafe fn classify_double(bits: *const u64, sign_out: *mut i32) -> i32 {
    let value = *bits;
    let hi = (value >> 32) as u32;
    *sign_out = (hi >> 31) as i32;
    let exponent = (hi >> 20) & 0x7ff;
    let mantissa_nonzero = (hi & 0x000f_ffff) != 0 || (value as u32) != 0;
    if exponent == 0x7ff {
        if mantissa_nonzero {
            1 // nan
        } else {
            2 // inf
        }
    } else {
        0 // zero / subnormal / normal — all finite for the formatter
    }
}

/// `format_exponent` — original: `FUN_080327e8` @ 0x080327e8 (116 bytes).
///
/// Appends the exponent suffix to `buf` at `len`: the conversion char
/// (`exp_char`: 'e' or 'E'), '+'/'-', then at least two exponent digits
/// (three when |exp| >= 100; original: signed divmod by 100 then by 10 —
/// FUN_08031568). Returns the new length.
unsafe fn format_exponent(buf: *mut u8, len: i32, exp: i32, exp_char: u8) -> i32 {
    *buf.add(len as usize) = exp_char;
    let mut magnitude = exp;
    let sign = if magnitude < 0 {
        magnitude = -magnitude;
        b'-'
    } else {
        b'+'
    };
    let mut i = len + 2;
    *buf.add((len + 1) as usize) = sign;
    if magnitude >= 100 {
        *buf.add(i as usize) = (magnitude / 100) as u8 + b'0';
        i = len + 3;
        magnitude %= 100;
    }
    *buf.add(i as usize) = (magnitude / 10) as u8 + b'0';
    *buf.add((i + 1) as usize) = (magnitude % 10) as u8 + b'0';
    i + 2
}

/// `%f` epilogue (original tail @ 0x08032b24): with a nonzero precision
/// or the `#` flag the decimal point stays, otherwise the length is
/// backed over it.
#[inline(always)]
unsafe fn finish_fixed(state: *mut PrintfState, flags: u32, len: i32) -> i32 {
    if (*state).precision != 0 || flags & FLAG_ALT_FORM != 0 {
        len
    } else {
        len - 1
    }
}

/// `format_float` — original: `FUN_0803285c` @ 0x0803285c (1264 bytes).
///
/// Lays out the float conversion into `buf` (32 bytes, supplied by the
/// wrapper) and returns the content length, `'<'`/`'>'` markers included.
/// Sets `state.prefix` (state+0x8) to the sign string, and state+0x0c /
/// state+0x10 to the deferred zero-run counts (-1 = none) as it goes.
/// Register-level signature matches the original: r0 = spec char,
/// r1 = buffer, r2 = pointer to the double's 8 bytes, r3 = state.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn format_float(
    spec: u8,
    buf: *mut u8,
    bits: *const u64,
    state: *mut PrintfState,
) -> i32 {
    let flags = (*state).flags;
    let dec_point = decimal_point();

    let mut negative: i32 = 0;
    let class = classify_double(bits, &mut negative);
    let prefix: *const u8 = if negative != 0 {
        b"-\0".as_ptr()
    } else if flags & FLAG_SHOW_SIGN != 0 {
        b"+\0".as_ptr()
    } else if flags & FLAG_SPACE_SIGN != 0 {
        b" \0".as_ptr()
    } else {
        b"\0".as_ptr()
    };
    (*state).prefix = prefix as *const *const u8;

    if class != 0 {
        // inf (2) / nan (1): three letters, case from the spec char
        // (uppercase conversions are all < 0x61), zero padding disabled.
        let text: &[u8; 4] = if class == 1 {
            if spec < 0x61 { b"NAN\0" } else { b"nan\0" }
        } else if spec < 0x61 {
            b"INF\0"
        } else {
            b"inf\0"
        };
        core::ptr::copy_nonoverlapping(text.as_ptr(), buf, 4);
        (*state).flags = flags & !FLAG_ZERO_PAD;
        return 3;
    }

    if spec == b'E' || spec == b'e' {
        // %e/%E: one leading digit, `precision` fraction digits, exponent.
        if (*state).precision > MAX_DIGITS {
            *frac_extra(state) = (*state).precision - MAX_DIGITS;
            (*state).precision = MAX_DIGITS;
        }
        let mut out = [0i32; 3];
        dtoa()(out.as_mut_ptr(), buf.add(1), bits, (*state).precision + 1, 0);
        let exp = out[0];
        let mut len = out[1] + 1;
        *buf = *buf.add(1);
        if (*state).precision != 0 || flags & FLAG_ALT_FORM != 0 {
            *buf.add(1) = dec_point;
        } else {
            len = 1;
        }
        if *frac_extra(state) > 0 {
            *buf.add(len as usize) = FRAC_ZEROS_MARK;
            len += 1;
        }
        return format_exponent(buf, len, exp, spec);
    }

    if spec == b'F' || spec == b'f' {
        // %f/%F: plain fixed notation built around the decimal exponent.
        let mut out = [0i32; 3];
        dtoa()(out.as_mut_ptr(), buf.add(1), bits, (*state).precision, 1);
        *buf = b'0';
        let exp = out[0];
        let ndigits = out[1];
        let precision = (*state).precision;
        let mut len: i32;
        if exp < 0 {
            let lead_zeros = -exp;
            if precision + 1 < lead_zeros {
                // Rounds to zero: "0." + `precision` deferred zeros.
                *buf.add(1) = dec_point;
                len = 2;
                *frac_extra(state) = precision;
            } else {
                len = precision - lead_zeros + 2;
                if ndigits + 1 < len {
                    *frac_extra(state) = len - ndigits - 1;
                    len = ndigits + 1;
                }
                if lead_zeros == 1 {
                    // 0.digits
                    let mut i = len;
                    while i > 0 {
                        *buf.add((i + 1) as usize) = *buf.add(i as usize);
                        i -= 1;
                    }
                    *buf = b'0';
                    len += 1;
                    *buf.add(1) = dec_point;
                } else {
                    // 0.<zeros>digits — the zeros are a deferred run.
                    let mut i = len;
                    while i > 0 {
                        *buf.add((i + 2) as usize) = *buf.add(i as usize);
                        i -= 1;
                    }
                    *buf = b'0';
                    *buf.add(1) = dec_point;
                    *buf.add(2) = INT_ZEROS_MARK;
                    len += 2;
                    *int_zeros(state) = lead_zeros - 1;
                }
            }
            if *frac_extra(state) < 1 {
                return finish_fixed(state, flags, len);
            }
        } else {
            len = precision + exp + 2;
            if len <= 18 {
                // Everything fits: digits, point, fraction.
                let mut i = 0;
                while i <= exp {
                    *buf.add(i as usize) = *buf.add((i + 1) as usize);
                    i += 1;
                }
                *buf.add((exp + 1) as usize) = dec_point;
                return finish_fixed(state, flags, len);
            }
            len = 18;
            if exp < 17 {
                // 17 significant digits shown; the rest of the fraction
                // becomes a deferred zero run.
                let mut i = 0;
                while i <= exp {
                    *buf.add(i as usize) = *buf.add((i + 1) as usize);
                    i += 1;
                }
                *buf.add((exp + 1) as usize) = dec_point;
                *frac_extra(state) = precision + exp - 16;
                if *frac_extra(state) == 0 {
                    return finish_fixed(state, flags, len);
                }
            } else {
                // More integer digits than the digit budget: defer the
                // missing integer zeros ('<'), keep the fraction.
                let mut i = 0;
                while i < 17 {
                    *buf.add(i as usize) = *buf.add((i + 1) as usize);
                    i += 1;
                }
                *buf.add(17) = INT_ZEROS_MARK;
                *int_zeros(state) = exp - 16;
                len = 19;
                *buf.add(18) = dec_point;
                if precision == 0 {
                    return finish_fixed(state, flags, len);
                }
                *frac_extra(state) = precision;
            }
        }
        *buf.add(len as usize) = FRAC_ZEROS_MARK;
        len += 1;
        return finish_fixed(state, flags, len);
    }

    // %g/%G (and any other spec, by the original's fall-through): pick
    // %f form when -4 <= exp < precision, %e form otherwise.
    let clamped = if (*state).precision < 1 {
        (*state).precision = 1;
        (*state).precision
    } else if (*state).precision > MAX_DIGITS {
        MAX_DIGITS // used for the dtoa call only, NOT stored back
    } else {
        (*state).precision
    };
    let mut out = [0i32; 3];
    dtoa()(out.as_mut_ptr(), buf.add(1), bits, clamped, 0);
    *buf = b'0';
    let exp = out[0];
    let ndigits = out[1];
    let mut len = ndigits + 1;
    let mut form = spec;
    if exp < (*state).precision && exp >= -4 {
        // %f form.
        form = b'f';
        if exp < 0 {
            // 0.<zeros>digits: shift right over the leading zeros.
            let lead = -exp;
            let mut i = len;
            while i >= 0 {
                *buf.add((i + lead) as usize) = *buf.add(i as usize);
                i -= 1;
            }
            len += lead;
            let mut i = 0;
            while i <= lead {
                *buf.add(i as usize) = b'0';
                i += 1;
            }
            *buf.add(1) = dec_point;
        } else if exp < ndigits {
            // Decimal point inside the digit run.
            let mut i = 0;
            while i <= exp {
                *buf.add(i as usize) = *buf.add((i + 1) as usize);
                i += 1;
            }
            *buf.add((exp + 1) as usize) = dec_point;
        } else {
            // More integer digits than produced digits: defer the
            // missing integer zeros.
            let mut i = 0;
            while i <= len {
                *buf.add(i as usize) = *buf.add((i + 1) as usize);
                i += 1;
            }
            *buf.add((len + 1) as usize) = dec_point;
            *buf.add((len - 1) as usize) = INT_ZEROS_MARK;
            *int_zeros(state) = exp - len + 2;
        }
    } else {
        // %e form: one leading digit, point, the rest.
        *buf = *buf.add(1);
        *buf.add(1) = dec_point;
    }
    if flags & FLAG_ALT_FORM == 0 {
        // No '#': strip trailing zeros, and a bare trailing point.
        *frac_extra(state) = -1;
        if *buf.add(len as usize) != dec_point {
            while *buf.add((len - 1) as usize) == b'0' {
                len -= 1;
            }
        }
        if *buf.add((len - 1) as usize) == dec_point {
            len -= 1;
        }
    } else if (*state).precision > MAX_DIGITS {
        *frac_extra(state) = (*state).precision - MAX_DIGITS;
        *buf.add(len as usize) = FRAC_ZEROS_MARK;
        len += 1;
    }
    if form == b'f' {
        return len;
    }
    // The %e form reuses the spec char two below 'g'/'G' ('e'/'E').
    format_exponent(buf, len, exp, form - 2)
}

/// `convert_fe` — original: `FUN_08032d70` @ 0x08032d70 (420 bytes).
///
/// Wrapper for all float conversions, called by the printf core as
/// `(state, spec, bits)` — see the module docs for the ABI. Defaults the
/// precision to 6 without `.`, formats into a 32-byte scratch buffer via
/// [`format_float`], then emits padding, sign prefix, and content with
/// the `'<'`/`'>'` markers expanded to zero runs.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn convert_fe(state: *mut PrintfState, spec: u8, bits: *const u64) {
    *int_zeros(state) = -1;
    *frac_extra(state) = -1;
    if (*state).flags & FLAG_PRECISION_GIVEN == 0 {
        (*state).precision = 6;
    }
    let mut buf = [0u8; 32];
    let len = format_float(spec, buf.as_mut_ptr(), bits, state);

    // The formatter stored the sign string char* at state+0x8.
    let prefix = (*state).prefix as *const u8;
    let prefix_len = (*prefix != 0) as i32;

    // Content length: buffer length plus the deferred zero runs (each
    // marker already occupies one buffer slot, hence the -1s).
    let mut extra = 0i32;
    let int_run = *int_zeros(state);
    if int_run > 0 {
        extra = int_run - 1;
    }
    let frac_run = *frac_extra(state);
    if frac_run > 0 {
        extra += frac_run - 1;
    }
    (*state).pad_remaining -= extra + len + prefix_len;

    // Right-justified without `0`: spaces before the prefix.
    if (*state).flags & FLAG_ZERO_PAD == 0 {
        pad_emit(state);
    }
    if prefix_len != 0 {
        ((*state).putc)(*prefix, (*state).putc_ctx);
        (*state).count += 1;
    }
    // With `0`: zeros between the prefix and the digits ("-00042").
    if (*state).flags & FLAG_ZERO_PAD != 0 {
        pad_emit(state);
    }
    let mut i = 0;
    while i < len {
        // Pointer read, not buf[i]: indexing would emit a
        // panic_bounds_check call the original does not have.
        let c = *buf.as_ptr().add(i as usize);
        if c == INT_ZEROS_MARK {
            let n = *int_zeros(state);
            let mut k = 0;
            while k < n {
                ((*state).putc)(b'0', (*state).putc_ctx);
                k += 1;
            }
            (*state).count += n;
        } else if c == FRAC_ZEROS_MARK {
            let n = *frac_extra(state);
            let mut k = 0;
            while k < n {
                ((*state).putc)(b'0', (*state).putc_ctx);
                k += 1;
            }
            (*state).count += n;
        } else {
            ((*state).putc)(c, (*state).putc_ctx);
            (*state).count += 1;
        }
        i += 1;
    }
    pad_emit_zero(state);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::printf_helpers::{
        PutcFn, FLAG_LEFT_JUSTIFY, FLAG_PRECISION_GIVEN, FLAG_ZERO_PAD,
    };
    use core::ffi::c_void;
    use std::string::String;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests: they swap DTOA / DECIMAL_POINT and share the
    /// recording sink pattern.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    struct Sink {
        buf: Vec<u8>,
    }

    unsafe extern "C" fn sink_putc(c: u8, ctx: *mut c_void) {
        (*(ctx as *mut Sink)).buf.push(c);
    }

    unsafe extern "C" fn dot_decimal_point() -> u8 {
        b'.'
    }

    unsafe extern "C" fn comma_decimal_point() -> u8 {
        b','
    }

    /// Mock dtoa back-end built on host f64 formatting (std). Honors the
    /// documented DTOA contract: out[0] = decimal exponent
    /// (value ~= D0.D1.. * 10^exp), out[1] = digits written, out[2] =
    /// style echo.
    unsafe fn mock_dtoa_impl(
        out: *mut i32,
        digits: *mut u8,
        bits: *const u64,
        ndigits: i32,
        style: i32,
    ) {
        let v = f64::from_bits(*bits).abs();
        if v == 0.0 {
            // The real back-end's zero-mantissa case.
            dtoa_not_ported(out, digits, bits, ndigits, style);
            return;
        }
        let (ds, exp): (String, i32) = if style == 0 {
            // Exactly `ndigits` significant digits, correctly rounded.
            let s = std::format!("{:.*e}", (ndigits - 1) as usize, v);
            let epos = s.find('e').expect("scientific notation");
            let mantissa: String = s[..epos].chars().filter(|c| *c != '.').collect();
            let e: i32 = s[epos + 1..].parse().expect("exponent");
            (mantissa, e)
        } else {
            // Fixed notation rounded to `ndigits` fractional digits.
            let s = std::format!("{:.*}", ndigits as usize, v);
            let (int_part, frac_part) = match s.find('.') {
                Some(p) => (&s[..p], &s[p + 1..]),
                None => (&s[..], ""),
            };
            let mut all: Vec<u8> = int_part.bytes().chain(frac_part.bytes()).collect();
            let mut e = int_part.len() as i32 - 1;
            while !all.is_empty() && all[0] == b'0' {
                all.remove(0);
                e -= 1;
            }
            if all.is_empty() {
                // Rounds to zero: same shape as the zero-mantissa case.
                dtoa_not_ported(out, digits, bits, ndigits, style);
                return;
            }
            if all.len() as i32 > MAX_DIGITS {
                // The real back-end falls back to a 17-significant-digit
                // production here; keep the leading 17.
                all.truncate(MAX_DIGITS as usize);
            }
            // NB: trailing zeros are KEPT. The real style-1 back-end
            // produces digits of the scaled value least-significant first
            // until exhaustion, so its digit run always covers every
            // fractional digit — the %f exp>=0 path of the formatter has
            // no zero-fill for missing digits, which proves the contract.
            (String::from_utf8(all).expect("ascii digits"), e)
        };
        for (i, b) in ds.bytes().enumerate() {
            *digits.add(i) = b;
        }
        *digits.add(ds.len()) = 0;
        *out = exp;
        *out.add(1) = ds.len() as i32;
        *out.add(2) = style;
    }

    unsafe extern "C" fn mock_dtoa(
        out: *mut i32,
        digits: *mut u8,
        bits: *const u64,
        ndigits: i32,
        style: i32,
    ) {
        mock_dtoa_impl(out, digits, bits, ndigits, style)
    }

    /// Install/restore guard for the two hooks.
    struct Hooks;

    impl Hooks {
        fn install(dtoa_mock: DtoaFn, dec: DecimalPointFn) -> Hooks {
            unsafe {
                *core::ptr::addr_of_mut!(DTOA) = dtoa_mock;
                *core::ptr::addr_of_mut!(DECIMAL_POINT) = dec;
            }
            Hooks
        }
    }

    impl Drop for Hooks {
        fn drop(&mut self) {
            unsafe {
                *core::ptr::addr_of_mut!(DTOA) = dtoa_not_ported;
                *core::ptr::addr_of_mut!(DECIMAL_POINT) = decimal_point_from_libspace;
            }
        }
    }

    fn make_state(flags: u32, width: i32, precision: i32, sink: &mut Sink) -> PrintfState {
        PrintfState {
            reserved_00: [0; 2],
            prefix: core::ptr::null(),
            reserved_0c: [0; 3],
            flags,
            putc: sink_putc as PutcFn,
            emit_str: None,
            putc_ctx: sink as *mut Sink as *mut c_void,
            reserved_28: [0; 3],
            pad_remaining: width, // raw field width, as the core leaves it
            precision,
            count: 0,
        }
    }

    /// Run convert_fe with the mock dtoa; returns (output, count).
    fn run(spec: u8, flags: u32, width: i32, precision: i32, value: f64) -> (Vec<u8>, i32) {
        run_with(mock_dtoa, dot_decimal_point, spec, flags, width, precision, value)
    }

    fn run_with(
        dtoa_mock: DtoaFn,
        dec: DecimalPointFn,
        spec: u8,
        flags: u32,
        width: i32,
        precision: i32,
        value: f64,
    ) -> (Vec<u8>, i32) {
        let _guard = lock();
        let _hooks = Hooks::install(dtoa_mock, dec);
        let mut sink = Sink { buf: Vec::new() };
        let bits = value.to_bits();
        let mut st = make_state(flags, width, precision, &mut sink);
        unsafe {
            convert_fe(&mut st, spec, &bits);
        }
        (sink.buf, st.count)
    }

    fn out(spec: u8, flags: u32, width: i32, precision: i32, value: f64) -> Vec<u8> {
        let (buf, count) = run(spec, flags, width, precision, value);
        assert_eq!(count, buf.len() as i32, "count must track emitted chars");
        buf
    }

    const P: u32 = FLAG_PRECISION_GIVEN;

    // ---- %e / %E ----

    #[test]
    fn e_default_precision_is_six() {
        assert_eq!(out(b'e', 0, 0, 0, 2.5), b"2.500000e+00");
        assert_eq!(out(b'E', 0, 0, 0, 2.5), b"2.500000E+00");
    }

    #[test]
    fn e_explicit_precision() {
        assert_eq!(out(b'e', P, 0, 2, 2.5), b"2.50e+00");
        assert_eq!(out(b'e', P, 0, 0, 2.5), b"2e+00");
        assert_eq!(out(b'e', P, 0, 1, 0.05), b"5.0e-02");
    }

    #[test]
    fn e_negative_and_exponent_widths() {
        assert_eq!(out(b'e', 0, 0, 0, -2.5), b"-2.500000e+00");
        assert_eq!(out(b'e', P, 0, 0, 1.0e10), b"1e+10");
        assert_eq!(out(b'e', P, 0, 2, 1.0e100), b"1.00e+100");
        assert_eq!(out(b'e', P, 0, 2, 1.0e-100), b"1.00e-100");
    }

    #[test]
    fn e_precision_over_17_uses_deferred_zeros() {
        // %.20e: 17 significant digits + 3 deferred zeros.
        assert_eq!(
            out(b'e', P, 0, 20, 1.5),
            b"1.50000000000000000000e+00"
        );
    }

    // ---- %f / %F ----

    #[test]
    fn f_basic_forms() {
        assert_eq!(out(b'f', 0, 0, 0, 2.5), b"2.500000");
        assert_eq!(out(b'F', 0, 0, 0, 2.5), b"2.500000");
        assert_eq!(out(b'f', P, 0, 2, 2.5), b"2.50");
        assert_eq!(out(b'f', P, 0, 0, 2.5), b"2");
        assert_eq!(out(b'f', P | FLAG_ALT_FORM, 0, 0, 2.5), b"2.");
    }

    #[test]
    fn f_small_values_and_leading_zeros() {
        assert_eq!(out(b'f', 0, 0, 0, 0.5), b"0.500000");
        assert_eq!(out(b'f', 0, 0, 0, 0.05), b"0.050000");
        assert_eq!(out(b'f', 0, 0, 0, 0.005), b"0.005000");
        // Rounds to zero at the given precision: "0." + deferred zeros.
        assert_eq!(out(b'f', P, 0, 3, 0.00004), b"0.000");
        assert_eq!(out(b'f', P, 0, 0, 0.00004), b"0");
    }

    #[test]
    fn rounding_carry_bumps_integer_part() {
        assert_eq!(out(b'f', P, 0, 2, 9.999), b"10.00");
        assert_eq!(out(b'e', P, 0, 2, 9.999), b"1.00e+01");
        assert_eq!(out(b'g', P, 0, 3, 9.999), b"10");
        assert_eq!(out(b'g', P, 0, 2, 99.9), b"1e+02");
    }

    #[test]
    fn f_zero_and_negative_zero() {
        assert_eq!(out(b'f', 0, 0, 0, 0.0), b"0.000000");
        assert_eq!(out(b'f', 0, 0, 0, -0.0), b"-0.000000");
        assert_eq!(out(b'e', 0, 0, 0, 0.0), b"0.000000e+00");
    }

    #[test]
    fn f_large_values() {
        assert_eq!(out(b'f', P, 0, 2, 123456.789), b"123456.79");
        // 17-digit integer part: deferred integer zeros via '<'.
        assert_eq!(
            out(b'f', 0, 0, 0, 1.0e18),
            b"1000000000000000000.000000"
        );
        assert_eq!(out(b'f', P, 0, 0, 1.0e18), b"1000000000000000000");
        // 17 significant digits, the exact binary value of 1/3.
        assert_eq!(
            out(b'f', P, 0, 17, 1.0 / 3.0),
            b"0.33333333333333331"
        );
        // Precision past 17 significant digits: deferred fraction zeros.
        assert_eq!(
            out(b'f', P, 0, 20, 1.5),
            b"1.50000000000000000000"
        );
    }

    // ---- %g / %G ----

    #[test]
    fn g_strips_trailing_zeros() {
        assert_eq!(out(b'g', 0, 0, 0, 2.5), b"2.5");
        assert_eq!(out(b'g', 0, 0, 0, 2.0), b"2");
        assert_eq!(out(b'g', 0, 0, 0, 2.5000001), b"2.5");
        assert_eq!(out(b'g', 0, 0, 0, 0.0001), b"0.0001");
        assert_eq!(out(b'g', 0, 0, 0, 100000.0), b"100000");
    }

    #[test]
    fn g_style_selection() {
        // exp < -4 or exp >= precision -> %e form.
        assert_eq!(out(b'g', 0, 0, 0, 0.00001), b"1e-05");
        assert_eq!(out(b'g', 0, 0, 0, 1.0e6), b"1e+06");
        assert_eq!(out(b'G', 0, 0, 0, 1.0e10), b"1E+10");
        assert_eq!(out(b'g', P, 0, 3, 1234.5), b"1.23e+03");
        assert_eq!(out(b'g', P, 0, 4, 1234.5), b"1234");
    }

    #[test]
    fn g_precision_rules() {
        // %.0g behaves as %.1g.
        assert_eq!(out(b'g', P, 0, 0, 2.5), b"2");
        assert_eq!(out(b'g', P, 0, 1, 0.0001), b"0.0001");
        // '#' keeps the point and the trailing zeros.
        assert_eq!(out(b'g', P | FLAG_ALT_FORM, 0, 6, 2.0), b"2.00000");
        assert_eq!(out(b'g', P | FLAG_ALT_FORM, 0, 1, 2.0), b"2.");
    }

    #[test]
    fn g_integer_digits_beyond_digit_run() {
        // exp >= ndigits: deferred integer zeros ('<' path).
        assert_eq!(out(b'g', P, 0, 3, 123400.0), b"1.23e+05");
        assert_eq!(out(b'g', P, 0, 6, 1234000.0), b"1.234e+06");
        assert_eq!(out(b'g', P, 0, 7, 1234000.0), b"1234000");
    }

    // ---- inf / nan ----

    #[test]
    fn inf_nan_text_and_case() {
        let inf = f64::from_bits(0x7ff0_0000_0000_0000);
        let nan = f64::from_bits(0x7ff8_0000_0000_0000);
        assert_eq!(out(b'f', 0, 0, 0, inf), b"inf");
        assert_eq!(out(b'e', 0, 0, 0, inf), b"inf");
        assert_eq!(out(b'g', 0, 0, 0, inf), b"inf");
        assert_eq!(out(b'F', 0, 0, 0, inf), b"INF");
        assert_eq!(out(b'E', 0, 0, 0, inf), b"INF");
        assert_eq!(out(b'G', 0, 0, 0, nan), b"NAN");
        assert_eq!(out(b'f', 0, 0, 0, nan), b"nan");
    }

    #[test]
    fn inf_nan_sign_prefixes() {
        let inf = f64::from_bits(0x7ff0_0000_0000_0000);
        let neg_inf = f64::from_bits(0xfff0_0000_0000_0000);
        let neg_nan = f64::from_bits(0xfff8_0000_0000_0000);
        assert_eq!(out(b'f', 0, 0, 0, neg_inf), b"-inf");
        assert_eq!(out(b'f', 0, 0, 0, neg_nan), b"-nan");
        assert_eq!(out(b'f', FLAG_SHOW_SIGN, 0, 0, inf), b"+inf");
        assert_eq!(out(b'f', FLAG_SPACE_SIGN, 0, 0, inf), b" inf");
    }

    #[test]
    fn inf_clears_zero_pad() {
        let inf = f64::from_bits(0x7ff0_0000_0000_0000);
        // '0' flag is cleared for inf/nan: space padding.
        assert_eq!(out(b'f', FLAG_ZERO_PAD, 8, 0, inf), b"     inf");
        assert_eq!(out(b'f', FLAG_LEFT_JUSTIFY, 8, 0, inf), b"inf     ");
        let _guard = lock();
        let _hooks = Hooks::install(mock_dtoa, dot_decimal_point);
        let mut sink = Sink { buf: Vec::new() };
        let bits = f64::INFINITY.to_bits();
        let mut st = make_state(FLAG_ZERO_PAD, 8, 0, &mut sink);
        unsafe { convert_fe(&mut st, b'f', &bits) };
        assert_eq!(st.flags & FLAG_ZERO_PAD, 0, "original clears the bit");
    }

    // ---- flags, width, precision combos ----

    #[test]
    fn sign_flags() {
        assert_eq!(out(b'f', FLAG_SHOW_SIGN, 0, 0, 2.5), b"+2.500000");
        assert_eq!(out(b'f', FLAG_SPACE_SIGN, 0, 0, 2.5), b" 2.500000");
        assert_eq!(out(b'e', FLAG_SHOW_SIGN, 0, 0, 2.5), b"+2.500000e+00");
        assert_eq!(out(b'g', FLAG_SHOW_SIGN, 0, 0, 2.5), b"+2.5");
    }

    #[test]
    fn width_space_padding() {
        assert_eq!(out(b'f', P, 12, 3, 2.5), b"       2.500");
        assert_eq!(out(b'f', P | FLAG_LEFT_JUSTIFY, 12, 3, 2.5), b"2.500       ");
        assert_eq!(out(b'e', P, 12, 2, 2.5), b"    2.50e+00");
    }

    #[test]
    fn width_zero_padding_sticks_to_sign() {
        assert_eq!(out(b'f', P | FLAG_ZERO_PAD, 12, 3, 2.5), b"00000002.500");
        assert_eq!(
            out(b'f', P | FLAG_ZERO_PAD | FLAG_SHOW_SIGN, 12, 3, 2.5),
            b"+0000002.500"
        );
        assert_eq!(
            out(b'f', P | FLAG_ZERO_PAD | FLAG_SPACE_SIGN, 12, 3, 2.5),
            b" 0000002.500"
        );
        assert_eq!(
            out(b'f', P | FLAG_ZERO_PAD, 12, 3, -2.5),
            b"-0000002.500"
        );
        assert_eq!(out(b'e', P | FLAG_ZERO_PAD, 12, 2, 2.5), b"00002.50e+00");
    }

    // ---- locale decimal point ----

    #[test]
    fn locale_decimal_point_override() {
        assert_eq!(
            out_with_comma(b'f', P, 0, 2, 2.5),
            b"2,50"
        );
        assert_eq!(
            out_with_comma(b'e', 0, 0, 0, 2.5),
            b"2,500000e+00"
        );
        assert_eq!(out_with_comma(b'g', 0, 0, 0, 2.5), b"2,5");
        assert_eq!(out_with_comma(b'f', P, 0, 3, 0.05), b"0,050");
    }

    fn out_with_comma(spec: u8, flags: u32, width: i32, precision: i32, value: f64) -> Vec<u8> {
        let (buf, _) = run_with(mock_dtoa, comma_decimal_point, spec, flags, width, precision, value);
        buf
    }

    // ---- default stub ----

    #[test]
    fn default_dtoa_stub_prints_zero() {
        let _guard = lock();
        // DTOA left at its documented default stub.
        unsafe {
            *core::ptr::addr_of_mut!(DECIMAL_POINT) = dot_decimal_point;
        }
        let mut sink = Sink { buf: Vec::new() };
        let bits = 1.5f64.to_bits();
        let mut st = make_state(0, 0, 0, &mut sink);
        unsafe { convert_fe(&mut st, b'f', &bits) };
        assert_eq!(sink.buf, b"0.000000");
        let mut sink = Sink { buf: Vec::new() };
        let mut st = make_state(0, 0, 0, &mut sink);
        unsafe { convert_fe(&mut st, b'e', &bits) };
        assert_eq!(sink.buf, b"0.000000e+00");
        let mut sink = Sink { buf: Vec::new() };
        let mut st = make_state(0, 0, 0, &mut sink);
        unsafe { convert_fe(&mut st, b'g', &bits) };
        assert_eq!(sink.buf, b"0");
        unsafe {
            *core::ptr::addr_of_mut!(DECIMAL_POINT) = decimal_point_from_libspace;
        }
    }
}

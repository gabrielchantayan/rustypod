//! `scan_float_conversion_veneer` — original: `thunk_FUN_08036348` at load
//! address `0x083ed1b8` (4 bytes: `b 0x08036348`). Raw `osos.dec` word
//! `0xeaf12462` decodes to that branch; `0x083ed1bc` is the next independently
//! linked function (`mov pc, lr`), establishing the true four-byte extent.
//!
//! Full-image A32 branch decoding finds two inbound plain `bl` calls
//! (`0x080331d0` and `0x08034c18`) and no predicated direct `bl` calls.
//!
//! Algorithm: preserve the complete incoming AAPCS register and stack state,
//! then tail-branch to the retail scan-conversion worker at `0x08036348`.
//! Its callers use it for `%f`/`%g` scan conversions; the worker remains
//! unported, so this veneer deliberately names only that verified role.
//!
//! # Deliberate deviations
//!
//! The payload cannot use the stock PC-relative `b`: its final link address is
//! unknown while assembling this source. The relocation-safe `ldr pc` veneer is
//! eight bytes rather than the stock four-byte branch, but preserves every
//! register, flags, stack word, and tail-call return edge.

/// Retail scan-conversion worker reached by the forwarding veneer.
pub const RETAIL_SCAN_FLOAT_CONVERSION_WORKER: u32 = 0x0803_6348;

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.scan_float_conversion_veneer,"ax",%progbits
    .p2align 2
    .globl scan_float_conversion_veneer
    .type scan_float_conversion_veneer,%function
scan_float_conversion_veneer:
    ldr pc, [pc, #-4]
    .word 0x08036348
    .size scan_float_conversion_veneer, . - scan_float_conversion_veneer
"#
);

#[cfg(test)]
mod tests {
    use super::RETAIL_SCAN_FLOAT_CONVERSION_WORKER;

    #[test]
    fn targets_the_verified_scan_conversion_worker() {
        assert_eq!(RETAIL_SCAN_FLOAT_CONVERSION_WORKER, 0x0803_6348);
    }
}

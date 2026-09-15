//! `no_op_destructor` — original: `FUN_0811f594` @ `0x0811f594` (4 bytes;
//! true extent `0x0811f594..0x0811f598`, followed by the distinct virtual
//! dispatch thunk at `0x0811f598`).
//!
//! Raw ARM is exactly `bx lr`: it neither reads arguments nor changes memory,
//! and preserves the incoming register state, including r0. Decoding every
//! ARM B/BL word in `osos.dec` finds five direct inbound calls, all plain
//! unconditional `bl`: `0x081959e8`, `0x08195c10`, `0x08195e1c`,
//! `0x08195f2c`, and `0x08195fa8`; there are no predicated direct `bl`
//! calls. Algorithm: return immediately. Deliberate deviations: none.

/// Performs the stock destructor's empty cleanup operation.
///
/// The firmware body is naked so its return preserves r0 exactly as `bx lr`.
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn no_op_destructor() {
    core::arch::naked_asm!("bx lr");
}

/// Host-callable equivalent of the empty target destructor.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn no_op_destructor() {}

#[cfg(test)]
mod tests {
    use super::no_op_destructor;

    #[test]
    fn performs_no_cleanup() {
        no_op_destructor();
    }
}

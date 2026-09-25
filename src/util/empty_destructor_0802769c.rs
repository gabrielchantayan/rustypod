//! `empty_destructor_0802769c` — original: `FUN_0802769c` @ `0x0802769c` (4 bytes;
//! true extent `0x0802769c..0x080276a0`, followed by the distinct empty function
//! at `0x080276a0`).
//!
//! Raw `osos.dec` is exactly `bx lr`: it neither reads arguments nor changes
//! memory, and preserves the incoming register state, including r0. Decoding
//! the raw A32 call words finds three inbound plain unconditional `bl` calls
//! and no predicated direct `bl` calls. Algorithm: return immediately.
//! Deliberate deviations: none.

/// Performs the stock destructor's empty cleanup operation.
///
/// The firmware body is naked so its return preserves r0 exactly as `bx lr`.
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_0802769c")]
pub unsafe extern "C" fn empty_destructor_0802769c() {
    core::arch::naked_asm!("bx lr");
}

/// Host-callable equivalent of the empty target destructor.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_0802769c")]
pub extern "C" fn empty_destructor_0802769c() {}

#[cfg(test)]
mod tests {
    use super::empty_destructor_0802769c;

    #[test]
    fn performs_no_cleanup() {
        let sentinel = 0x2769_c000u32;
        empty_destructor_0802769c();
        assert_eq!(sentinel, 0x2769_c000);
    }
}

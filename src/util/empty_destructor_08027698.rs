//! `empty_destructor_08027698` — original: `FUN_08027698` @ `0x08027698` (4 bytes;
//! true extent `0x08027698..0x0802769c`, followed by a distinct empty function
//! at `0x0802769c`).
//!
//! Raw `osos.dec` is exactly `bx lr`: it neither reads arguments nor changes
//! memory, and preserves the incoming register state, including r0. Decoding
//! every A32 B/BL word in `osos.dec` finds four inbound plain unconditional
//! `bl` calls and no predicated direct `bl` calls. Algorithm: return
//! immediately. Deliberate deviations: none.

/// Performs the stock destructor's empty cleanup operation.
///
/// The firmware body is naked so its return preserves r0 exactly as `bx lr`.
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_08027698")]
pub unsafe extern "C" fn empty_destructor_08027698() {
    core::arch::naked_asm!("bx lr");
}

/// Host-callable equivalent of the empty target destructor.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_08027698")]
pub extern "C" fn empty_destructor_08027698() {}

#[cfg(test)]
mod tests {
    use super::empty_destructor_08027698;

    #[test]
    fn performs_no_cleanup() {
        let sentinel = 0x2769_8000u32;
        empty_destructor_08027698();
        assert_eq!(sentinel, 0x2769_8000);
    }
}

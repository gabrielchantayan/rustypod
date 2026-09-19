//! `empty_destructor_08057164` — original: `FUN_08057164` @ `0x08057164` (4 bytes;
//! true extent `0x08057164..0x08057168`, followed by the distinct global-state
//! refresh routine at `0x08057168`).
//!
//! Raw `osos.dec` is exactly `bx lr`: it neither reads arguments nor changes
//! memory, and preserves the incoming register state, including r0. Decoding
//! every A32 B/BL word in `osos.dec` finds two inbound plain unconditional
//! `bl` calls (`0x08038f04`, `0x08038f24`) and two predicated `blne` calls
//! (`0x08038f1c`, `0x08038f30`). Algorithm: return immediately. Deliberate
//! deviations: none.

/// Performs the stock destructor's empty cleanup operation.
///
/// The firmware body is naked so its return preserves r0 exactly as `bx lr`.
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_08057164")]
pub unsafe extern "C" fn empty_destructor_08057164() {
    core::arch::naked_asm!("bx lr");
}

/// Host-callable equivalent of the empty target destructor.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_08057164")]
pub extern "C" fn empty_destructor_08057164() {}

#[cfg(test)]
mod tests {
    use super::empty_destructor_08057164;

    #[test]
    fn performs_no_cleanup() {
        let sentinel = 0x5716_4000u32;
        empty_destructor_08057164();
        assert_eq!(sentinel, 0x5716_4000);
    }
}

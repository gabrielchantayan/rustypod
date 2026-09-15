//! Single-bit MMIO register update.
//!
//! `mmio_bit_write` — original: `FUN_0827281c` @ 0x0827281c (36 bytes,
//! 0x0827281c..0x08272840; the separately linked next function begins with
//! `ldr r3, [r0]` at 0x08272840). Five plain `bl` call sites and zero
//! predicated `bl` call sites, decoded from the raw ARM words in `osos.dec`.
//!
//! Loads the target register address through `register`, then updates one bit:
//! a zero `value` clears it and every nonzero value sets it. The register shift
//! uses only the low byte of `bit`; ARM produces a zero mask for shifts 32
//! through 255, rather than Rust's modulo-32 `wrapping_shl` behavior.
//!
//! Deliberate deviations: volatile accesses preserve the target's MMIO read and
//! write semantics; the stock instructions are ordinary `ldr`/`str`.

use core::ptr;

/// Updates bit `bit` of the MMIO register addressed by `register`.
///
/// # Safety
///
/// `register` must point to a valid target-width register address. The target
/// must permit a volatile 32-bit read followed by a volatile 32-bit write.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mmio_bit_write(register: *mut *mut u32, bit: u32, value: u32) {
    let register = ptr::read(register);
    let shift = bit & 0xff;
    let mask = if shift < 32 { 1u32 << shift } else { 0 };
    let bits = ptr::read_volatile(register);
    ptr::write_volatile(register, if value == 0 { bits & !mask } else { bits | mask });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_only_the_requested_bit_for_clear_and_nonzero_set_requests() {
        let mut bits = 0xa5a5_5a5a;
        let mut register = core::ptr::addr_of_mut!(bits);

        unsafe {
            mmio_bit_write(core::ptr::addr_of_mut!(register), 1, 0);
            assert_eq!(bits, 0xa5a5_5a58);

            mmio_bit_write(core::ptr::addr_of_mut!(register), 30, 0xfeed_beef);
            assert_eq!(bits, 0xe5a5_5a58);
        }
    }

    #[test]
    fn high_byte_shift_counts_leave_the_register_unchanged() {
        for bit in [32, 63, 128, 255, u32::MAX] {
            let mut bits = 0x1234_5678;
            let mut register = core::ptr::addr_of_mut!(bits);
            unsafe { mmio_bit_write(core::ptr::addr_of_mut!(register), bit, 1) };
            assert_eq!(bits, 0x1234_5678, "bit {bit}");
        }

        let mut bits = 0x1234_5678;
        let mut register = core::ptr::addr_of_mut!(bits);
        unsafe { mmio_bit_write(core::ptr::addr_of_mut!(register), 256, 1) };
        assert_eq!(bits, 0x1234_5679, "only the low byte selects the shift");
    }
}
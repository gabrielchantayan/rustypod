//! Checked scaling by a runtime configuration word.
//!
//! `scale_by_runtime_multiplier_checked` — retailOS `FUN_0808432c` at load
//! address **0x0808432c**. Raw `osos.dec` establishes the 52-byte extent:
//! 48 instruction bytes at `0x0808432c..0x0808435c`, followed by the literal
//! `0x08a09b90` at `0x08084360`; the distinct next function starts at
//! `0x08084364`. Decoding every ARM `B`/`BL` immediate finds exactly six
//! direct inbound calls, all unconditional `bl` at `0x08088c84`,
//! `0x08088ccc`, `0x08088d44`, `0x08088da8`, `0x08088dec`, and `0x08088e78`.
//! There are no predicated direct calls.
//!
//! The helper volatile-loads the runtime multiplier at `0x08a09b94`, computes
//! the full unsigned 32-by-32-bit product, and stores its low word only when
//! its high word is zero. A product above `u32::MAX` leaves the output cell
//! untouched and returns status `0x55`; successful calls return zero.
//!
//! The surrounding configuration builder establishes only that this word is a
//! runtime scale factor; its owning subsystem is unrecovered and deliberately
//! not invented. Deliberate deviation: host builds use replaceable private
//! backing for the firmware RAM word.

use core::ptr;

/// Firmware runtime multiplier word addressed by the original literal pool.
#[cfg(target_os = "none")]
const RUNTIME_MULTIPLIER_ADDRESS: *const u32 = 0x08a0_9b94usize as *const u32;

/// Host backing for the runtime multiplier word.
#[cfg(not(target_os = "none"))]
static mut HOST_RUNTIME_MULTIPLIER: u32 = 0;

#[inline(always)]
unsafe fn runtime_multiplier() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { ptr::read_volatile(RUNTIME_MULTIPLIER_ADDRESS) }
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::read_volatile(ptr::addr_of!(HOST_RUNTIME_MULTIPLIER)) }
    }
}

/// scale_by_runtime_multiplier_checked — retailOS `FUN_0808432c` @
/// `0x0808432c` (52 bytes; six direct unconditional `bl` callers).
///
/// Multiplies `value` by the firmware runtime multiplier. On success writes
/// the exact `u32` result to `output` and returns zero. On overflow returns
/// `0x55` without modifying `output`. Like retailOS, this function has no
/// null-output guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.scale_by_runtime_multiplier_checked")]
#[inline(never)]
pub unsafe extern "C" fn scale_by_runtime_multiplier_checked(value: u32, output: *mut u32) -> u32 {
    let product = value as u64 * unsafe { runtime_multiplier() } as u64;
    if (product >> 32) != 0 {
        return 0x55;
    }

    unsafe { ptr::write(output, product as u32) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static RUNTIME_MULTIPLIER_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe fn install_runtime_multiplier(value: u32) {
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(HOST_RUNTIME_MULTIPLIER), value) };
    }

    #[test]
    fn stores_exact_products_that_fit_in_one_word() {
        let _guard = RUNTIME_MULTIPLIER_TEST_LOCK.lock();

        unsafe { install_runtime_multiplier(0x1_0001) };
        let mut output = 0;
        assert_eq!(unsafe { scale_by_runtime_multiplier_checked(0xfffe, &mut output) }, 0);
        assert_eq!(output, 0xfffe_fffe);

        unsafe { install_runtime_multiplier(1) };
        output = 0;
        assert_eq!(unsafe { scale_by_runtime_multiplier_checked(u32::MAX, &mut output) }, 0);
        assert_eq!(output, u32::MAX);

        unsafe { install_runtime_multiplier(0) };
        output = u32::MAX;
        assert_eq!(unsafe { scale_by_runtime_multiplier_checked(u32::MAX, &mut output) }, 0);
        assert_eq!(output, 0);
    }

    #[test]
    fn accepts_the_largest_product_that_fits() {
        let _guard = RUNTIME_MULTIPLIER_TEST_LOCK.lock();

        unsafe { install_runtime_multiplier(0x1_0000) };
        let mut output = 0;
        assert_eq!(unsafe { scale_by_runtime_multiplier_checked(0xffff, &mut output) }, 0);
        assert_eq!(output, 0xffff_0000);
    }

    #[test]
    fn reports_overflow_without_writing_output() {
        let _guard = RUNTIME_MULTIPLIER_TEST_LOCK.lock();

        unsafe { install_runtime_multiplier(0x1_0000) };
        let mut output = 0xa5a5_5a5a;
        assert_eq!(unsafe { scale_by_runtime_multiplier_checked(0x1_0000, &mut output) }, 0x55);
        assert_eq!(output, 0xa5a5_5a5a);
    }
}

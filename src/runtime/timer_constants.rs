//! I2S register-base selector @ 0x08004ca4.
//!
//! The recovered caller, `FUN_0800881c`, chooses one of three I2S interfaces
//! before updating its interrupt masks. It supplies interface-specific masks
//! 0x80, 0x400, and 0x10000. The decoded literals are the S5L8702 I2S base
//! plus its documented interface offsets: interface 0 at 0x3ca0_0000,
//! interface 1 at +0x300000, and interface 2 at +0xa00000.

/// I2S interface-0 register block selected by selector 0 and all defaults.
pub const I2S0_REGISTER_BASE: u32 = 0x3ca0_0000;
/// I2S interface-1 register block selected by selector 1.
pub const I2S1_REGISTER_BASE: u32 = 0x3cd0_0000;
/// I2S interface-2 register block selected by selector 2.
pub const I2S2_REGISTER_BASE: u32 = 0x3d40_0000;

/// Firmware literal-pool addresses loaded by the original for interfaces 1
/// and 0, respectively.
#[cfg(target_os = "none")]
const I2S1_REGISTER_BASE_LITERAL: *const u32 = 0x0800_4cc0 as *const u32;
#[cfg(target_os = "none")]
const I2S0_REGISTER_BASE_LITERAL: *const u32 = 0x0800_4cc4 as *const u32;

/// Deterministic host replacement for the firmware literal-pool words. Hosts
/// do not map retailOS at 0x08000000; tests replace these words to verify that
/// the selector loads the same literal selected by the ARM conditionals.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct I2sRegisterBaseLiterals {
    pub interface1: u32,
    pub interface0: u32,
}

#[cfg(not(target_os = "none"))]
pub static mut HOST_I2S_REGISTER_BASE_LITERALS: I2sRegisterBaseLiterals =
    I2sRegisterBaseLiterals {
        interface1: I2S1_REGISTER_BASE,
        interface0: I2S0_REGISTER_BASE,
    };

#[cfg(target_os = "none")]
#[inline(always)]
fn i2s_register_base_literals() -> (u32, u32) {
    unsafe {
        (
            core::ptr::read_volatile(I2S1_REGISTER_BASE_LITERAL),
            core::ptr::read_volatile(I2S0_REGISTER_BASE_LITERAL),
        )
    }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
fn i2s_register_base_literals() -> (u32, u32) {
    unsafe {
        let literals = core::ptr::read_volatile(core::ptr::addr_of!(
            HOST_I2S_REGISTER_BASE_LITERALS
        ));
        (literals.interface1, literals.interface0)
    }
}

/// select_i2s_interrupt_register_base — original: `FUN_08004ca4` @
/// 0x08004ca4 (28 bytes). Reference:
/// `ipod-decomp/decomp/c/000/08004ca4_FUN_08004ca4.c` and
/// `ipod-decomp/decomp/osos.asm` @ 0x08004ca4..0x08004cbc.
///
/// Selects the I2S register block used by the interrupt-mask updater:
/// selector 1 returns I2S1 (0x3cd0_0000), selector 2 returns I2S2
/// (0x3d40_0000), and every other selector — including selector 0 — returns
/// I2S0 (0x3ca0_0000). This is the original comparison order: selector 1
/// reaches its literal-pool load first, selector 2 reaches its inlined
/// immediate, and the remaining values load the I2S0 literal.
///
/// # Deviation
///
/// The target implementation volatile-loads the same two retailOS
/// literal-pool words at 0x08004cc0 and 0x08004cc4. Host builds use the
/// replaceable [`HOST_I2S_REGISTER_BASE_LITERALS`] seam because that firmware
/// address range is unmapped; this changes only the source of the words, not
/// selector precedence or returned values.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn select_i2s_interrupt_register_base(selector: u32) -> u32 {
    let (interface1, interface0) = i2s_register_base_literals();
    if selector == 1 {
        interface1
    } else if selector == 2 {
        I2S2_REGISTER_BASE
    } else {
        interface0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static LITERALS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn selector_returns_decoded_i2s_interface_bases() {
        let _lock = LITERALS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(
                HOST_I2S_REGISTER_BASE_LITERALS
            ));
            HOST_I2S_REGISTER_BASE_LITERALS = I2sRegisterBaseLiterals {
                interface1: I2S1_REGISTER_BASE,
                interface0: I2S0_REGISTER_BASE,
            };

            assert_eq!(select_i2s_interrupt_register_base(0), I2S0_REGISTER_BASE);
            assert_eq!(select_i2s_interrupt_register_base(1), I2S1_REGISTER_BASE);
            assert_eq!(select_i2s_interrupt_register_base(2), I2S2_REGISTER_BASE);

            HOST_I2S_REGISTER_BASE_LITERALS = saved;
        }
    }

    #[test]
    fn selector_loads_the_correct_literal_and_preserves_default_path() {
        let _lock = LITERALS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(
                HOST_I2S_REGISTER_BASE_LITERALS
            ));
            HOST_I2S_REGISTER_BASE_LITERALS = I2sRegisterBaseLiterals {
                interface1: 0xaaaa_0000,
                interface0: 0xbbbb_0000,
            };

            assert_eq!(select_i2s_interrupt_register_base(1), 0xaaaa_0000);
            for selector in [0, 3, u32::MAX] {
                assert_eq!(
                    select_i2s_interrupt_register_base(selector),
                    0xbbbb_0000,
                    "selector {selector:#010x} must take the original default path"
                );
            }
            assert_eq!(
                select_i2s_interrupt_register_base(2),
                I2S2_REGISTER_BASE,
                "selector 2 must bypass both literal-pool words"
            );

            HOST_I2S_REGISTER_BASE_LITERALS = saved;
        }
    }
}

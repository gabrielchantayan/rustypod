//! `gpio_pin_interrupt_set` — `FUN_08274374` @ `0x08274374`.
//! True extent: 28 bytes, seven ARM words, ending before the independently
//! entered `0x08274390` (tail branch from `0x0811f7dc`). Raw decoding finds
//! zero outbound plain or predicated BLs, two predicated tail branches, and
//! two inbound plain BLs (`0x0811f7d0`, `0x0813b114`), no predicated BLs.
//!
//! Read the pin-ID byte. Sentinel 200 returns 200 without touching hardware.
//! Zero enable tail-calls `0x0836b5fc`, clearing the selected bit in the
//! `0x39a000c0` bank. Nonzero enable becomes one and tail-calls `0x0836b634`,
//! setting the selected bit in banks `0x39a000e0`, `0x39a000c0`, `0x39a000a0`.
//! Both targets reverse byte positions within each 32-bit bitmap word and
//! select word `6 - (pin >> 5)`; both return zero.
//!
//! Deliberate deviations: the still-unported targets use absolute literal
//! veneers on ARM and installed callback seams on host. Rust return calls
//! preserve the tail-call result without requiring identical instruction layout.

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_gpio_interrupt_clear(pin: u32) -> u32;
    fn retail_gpio_interrupt_arm(pin: u32, enabled: u32) -> u32;
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_gpio_interrupt_clear
    .type retail_gpio_interrupt_clear, %function
retail_gpio_interrupt_clear:
    ldr pc, [pc, #-4]
    .word 0x0836b5fc
    .size retail_gpio_interrupt_clear, . - retail_gpio_interrupt_clear
    .p2align 2
    .globl retail_gpio_interrupt_arm
    .type retail_gpio_interrupt_arm, %function
retail_gpio_interrupt_arm:
    ldr pc, [pc, #-4]
    .word 0x0836b634
    .size retail_gpio_interrupt_arm, . - retail_gpio_interrupt_arm
"#
);

#[cfg(not(target_arch = "arm"))]
pub static mut HOST_GPIO_INTERRUPT_CLEAR: Option<unsafe extern "C" fn(u32) -> u32> = None;
#[cfg(not(target_arch = "arm"))]
pub static mut HOST_GPIO_INTERRUPT_ARM: Option<unsafe extern "C" fn(u32, u32) -> u32> = None;

/// Sets interrupt enable for the pin byte at `pin_id`; returns 200 for no pin.
///
/// # Safety
/// `pin_id` must point to a readable byte. Non-sentinel pins must be below 224
/// and the retail bitmap registers must be accessible. Host callers must
/// install the corresponding callback and serialize changes to those seams.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gpio_pin_interrupt_set(pin_id: *const u8, enable: u32) -> u32 {
    let pin = *pin_id as u32;
    if pin == 200 {
        return pin;
    }
    #[cfg(target_arch = "arm")]
    {
        if enable == 0 {
            retail_gpio_interrupt_clear(pin)
        } else {
            retail_gpio_interrupt_arm(pin, 1)
        }
    }
    #[cfg(not(target_arch = "arm"))]
    {
        if enable == 0 {
            let clear = core::ptr::read_volatile(core::ptr::addr_of!(HOST_GPIO_INTERRUPT_CLEAR));
            clear.expect("install GPIO interrupt clear seam")(pin)
        } else {
            let arm = core::ptr::read_volatile(core::ptr::addr_of!(HOST_GPIO_INTERRUPT_ARM));
            arm.expect("install GPIO interrupt arm seam")(pin, 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Model the independently decoded retail callees' three register banks.
    static mut BANKS: [[u32; 8]; 3] = [[0; 8]; 3];

    fn location(pin: u32) -> (usize, u32) {
        let word = 6 - (pin / 32) as usize;
        let bit = (3 - (pin / 8) % 4) * 8 + pin % 8;
        (word, 1 << bit)
    }

    unsafe extern "C" fn clear(pin: u32) -> u32 {
        let (word, mask) = location(pin);
        BANKS[1][word] &= !mask;
        0
    }

    unsafe extern "C" fn arm(pin: u32, enabled: u32) -> u32 {
        let (word, mask) = location(pin);
        BANKS[2][word] |= enabled * mask;
        BANKS[1][word] |= mask;
        BANKS[0][word] |= mask;
        0
    }

    #[test]
    fn sentinel_and_all_valid_pin_bits_preserve_unrelated_registers() {
        unsafe {
            // Missing seams make any accidental sentinel dispatch fail.
            for enable in [0, 1, 2, u32::MAX] {
                assert_eq!(gpio_pin_interrupt_set(&200, enable), 200);
            }
            HOST_GPIO_INTERRUPT_CLEAR = Some(clear);
            HOST_GPIO_INTERRUPT_ARM = Some(arm);
            for pin in 0u8..224 {
                if pin == 200 { continue; }
                let (word, mask) = location(pin as u32);
                for enable in [0, 1, 2, u32::MAX] {
                    let initial = if enable == 0 { 0xffff_ffff } else { 0x55aa_33cc & !mask };
                    BANKS = [[initial; 8]; 3];
                    assert_eq!(gpio_pin_interrupt_set(&pin, enable), 0);
                    let actual = BANKS;
                    for bank in 0..3 {
                        for index in 0..8 {
                            let expected = if index != word { initial }
                                else if enable != 0 { initial | mask }
                                else if bank == 1 { initial & !mask }
                                else { initial };
                            assert_eq!(actual[bank][index], expected,
                                "pin {pin}, enable {enable}, bank {bank}, word {index}");
                        }
                    }
                }
            }
            HOST_GPIO_INTERRUPT_CLEAR = None;
            HOST_GPIO_INTERRUPT_ARM = None;
        }
    }
}

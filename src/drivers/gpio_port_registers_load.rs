//! `gpio_port_registers_load` — original: `FUN_083699a8` @ 0x083699a8
//! (60 bytes; next function begins at 0x083699e8; 2 unconditional and 1
//! predicated inbound `bl` call sites, zero outbound calls, binary-scanned).
//!
//! Copies the sixteen 8-byte GPIO port configuration records at `records` into
//! the GPIO controller's sixteen 0x20-byte port blocks. Each record's aligned
//! word becomes the block's word 0; its bytes 4 and 5 are zero-extended into
//! words 3 and 4. The other register words remain untouched.
//!
//! On-device, destination writes are volatile MMIO stores. The host build uses
//! a private register-file stand-in so the exported entry point is testable.
//! `black_box(16)` preserves the retail loop shape against LLVM unrolling; it
//! does not alter target behavior.

use super::gpio_cmd::GPIO_BASE;

const GPIO_PORT_COUNT: usize = 16;
const GPIO_PORT_STRIDE: usize = 0x20;
const GPIO_PORT_WORDS: usize = GPIO_PORT_STRIDE / core::mem::size_of::<u32>();

#[cfg(not(target_arch = "arm"))]
static mut HOST_GPIO_PORTS: [u32; GPIO_PORT_COUNT * GPIO_PORT_WORDS] =
    [0; GPIO_PORT_COUNT * GPIO_PORT_WORDS];

#[inline(always)]
unsafe fn gpio_port_word(port: usize, word: usize) -> *mut u32 {
    #[cfg(target_arch = "arm")]
    {
        (GPIO_BASE as *mut u32).add(port * GPIO_PORT_WORDS + word)
    }

    #[cfg(not(target_arch = "arm"))]
    {
        core::ptr::addr_of_mut!(HOST_GPIO_PORTS[port * GPIO_PORT_WORDS + word])
    }
}

/// Loads sixteen GPIO port register blocks from sixteen 8-byte records.
/// `records` must point to 128 readable bytes, aligned for `u32` loads.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gpio_port_registers_load(records: *const u8) {
    let mut port = 0;
    while port < core::hint::black_box(GPIO_PORT_COUNT) {
        let record = records.add(port * 8);
        core::ptr::write_volatile(gpio_port_word(port, 3), *record.add(4) as u32);
        core::ptr::write_volatile(gpio_port_word(port, 4), *record.add(5) as u32);
        core::ptr::write_volatile(gpio_port_word(port, 0), *(record as *const u32));
        port += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_all_records_without_touching_other_register_words() {
        let mut records = [0u32; GPIO_PORT_COUNT * 2];
        for port in 0..GPIO_PORT_COUNT {
            records[port * 2] = 0x1020_3040 ^ (port as u32 * 0x0101_0101);
            records[port * 2 + 1] = (port as u32) << 8 | (0x80 + port as u32);
        }

        unsafe {
            HOST_GPIO_PORTS.fill(0xdead_beef);
            gpio_port_registers_load(records.as_ptr() as *const u8);
            for port in 0..GPIO_PORT_COUNT {
                let base = port * GPIO_PORT_WORDS;
                assert_eq!(HOST_GPIO_PORTS[base], records[port * 2]);
                assert_eq!(HOST_GPIO_PORTS[base + 3], 0x80 + port as u32);
                assert_eq!(HOST_GPIO_PORTS[base + 4], port as u32);
                for word in [1, 2, 5, 6, 7] {
                    assert_eq!(HOST_GPIO_PORTS[base + word], 0xdead_beef);
                }
            }
        }
    }
}
//! USB IN endpoint transfer-size rebase — retail FUN_08107914 @ 0x08107914.
//! True extent 0x08107914..0x0810799c: 124 instruction bytes and 12 literal
//! bytes before the next function. Two incoming plain BLs at 0x08107ecc
//! and 0x08108168; zero predicated incoming BLs and zero outgoing BLs.
//!
//! Extract the remaining packet count from DIEPTSIZ, then recompute bytes
//! from the saved endpoint byte count at context +0x38 and all but the last
//! packet. Endpoint zero uses 64-byte packets and a seven-bit old size;
//! other endpoints use DIEPCTL's low eleven bits and a nineteen-bit size.
//! Write the new size/count with bit 29 set, optionally adjust DIEPDMA by
//! old size minus new size, and return the new size (not void as in Ghidra).
//! Zero packets clears DIEPTSIZ and returns zero without reading context.
//! Deviations: volatile aligned MMIO; isolated host register storage. No
//! validation or arithmetic changes; all arithmetic wraps as in A32.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTERS: [u32; 9 * 8] = [0; 9 * 8];

#[inline(always)]
fn registers() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x3840_0900 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>() }
}

#[inline(always)]
unsafe fn rebase(context: *const u32, endpoint: u32, adjust_dma: u32, base: *mut u32) -> u32 {
    let bank = base.add(endpoint as usize * 8);
    let size_register = bank.add(4);
    let old_size = size_register.read_volatile();
    let packets = (old_size >> 19) & !0x1c00;
    if packets == 0 {
        size_register.write_volatile(0);
        return 0;
    }
    // Retail reads DIEPCTL even for endpoint zero, before reading context.
    let control = bank.read_volatile();
    let saved_bytes = context.add(0x38 / 4 + endpoint as usize).read();
    let packet_bytes = if endpoint == 0 { 64 } else { control & 0x7ff };
    let new_size = packet_bytes.wrapping_mul(packets - 1).wrapping_add(saved_bytes);
    let old_bytes = old_size & if endpoint == 0 { 0x7f } else { 0x7ffff };
    size_register.write_volatile(new_size | (packets << 19) | 0x2000_0000);
    if adjust_dma != 0 {
        let dma = bank.add(5);
        let address = dma.read_volatile();
        dma.write_volatile(address.wrapping_sub(new_size.wrapping_sub(old_bytes)));
    }
    new_size
}

/// # Safety
/// Endpoint must select a valid controller bank (0..=8). For a nonzero
/// packet count, context must be aligned/readable at word 14 + endpoint.
/// MMIO access (or the host register fixture) must be serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_in_endpoint_transfer_rebase(
    context: *const u32, endpoint: u32, adjust_dma: u32,
) -> u32 {
    rebase(context, endpoint, adjust_dma, registers())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_packets_ignores_flags_context_and_dma() {
        for endpoint in 0..=8 {
            let mut bank = [0xa5a5_1234; 9 * 8];
            bank[endpoint * 8 + 4] = 0xe007_ffff;
            let mut expected = bank;
            expected[endpoint * 8 + 4] = 0;
            assert_eq!(unsafe { rebase(ptr::null(), endpoint as u32, 1, bank.as_mut_ptr()) }, 0);
            assert_eq!(bank, expected);
        }
    }

    #[test]
    fn packet_counts_masks_dma_wrap_and_neighbor_preservation() {
        for endpoint in 0..=8 {
            for packets in [1u32, 2, 17, 1023] {
                for control in [0, 64, 512, 0xffff_fabc] {
                    for saved in [0u32, 1, 127, 0xffff_fff0] {
                        for adjust in [0, 1, u32::MAX] {
                            let mut context = [0x1357_2468; 23];
                            context[14 + endpoint] = saved;
                            let mut bank = [0x7654_3210; 9 * 8];
                            let index = endpoint * 8;
                            bank[index] = control;
                            bank[index + 4] = 0xe007_ffff | (packets << 19);
                            bank[index + 5] = 3;
                            let mut expected = bank;
                            let packet_bytes = if endpoint == 0 { 64u64 } else { (control & 2047) as u64 };
                            let size = (packet_bytes * (packets as u64 - 1) + saved as u64) as u32;
                            expected[index + 4] = size | (packets << 19) | 0x2000_0000;
                            if adjust != 0 {
                                let old_bytes = if endpoint == 0 { 127u32 } else { 524287 };
                                expected[index + 5] = 3u32.wrapping_add(old_bytes).wrapping_sub(size);
                            }
                            let result = unsafe { rebase(context.as_ptr(), endpoint as u32, adjust, bank.as_mut_ptr()) };
                            assert_eq!(result, size);
                            assert_eq!(bank, expected);
                            assert_eq!(context[14 + endpoint], saved);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn public_entry_rebases_endpoint_zero_and_adjusts_dma() {
        unsafe {
            let base = registers();
            base.write_volatile(u32::MAX);
            base.add(4).write_volatile((3 << 19) | 7);
            base.add(5).write_volatile(1000);
            let mut context = [0u32; 15];
            context[14] = 9;
            assert_eq!(usb_in_endpoint_transfer_rebase(context.as_ptr(), 0, 1), 137);
            assert_eq!(base.add(4).read_volatile(), (3 << 19) | 0x2000_0000 | 137);
            assert_eq!(base.add(5).read_volatile(), 870);
        }
    }
}

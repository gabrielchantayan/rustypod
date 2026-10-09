//! USB OUT endpoint zero rearm — retail FUN_080efb94 @ 0x080efb94.
//! True extent 0x080efb94..0x080efbc8: 44 instruction bytes plus 8 literal
//! bytes, followed by the next function's PUSH. Two plain incoming BLs
//! (0x080817c8, 0x08108240), zero predicated incoming or outgoing BLs.
//!
//! Write DOEPTSIZ0 = 0x60080040, read the saved DMA address at 0x08a09f8c,
//! clear its high bit and write DOEPDMA0, then read/OR/write DOEPCTL0
//! with 0x88000000. No arguments, return value, or callee seams.
//! Deviations: volatile aligned accesses preserve the original access
//! order; host builds substitute isolated register and DMA-word storage.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTERS: [u32; 8] = [0; 8];
#[cfg(not(target_os = "none"))]
static mut HOST_DMA_ADDRESS: u32 = 0;

#[inline(always)]
fn registers() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x3840_0b00 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>() }
}

#[inline(always)]
fn saved_dma_address() -> *const u32 {
    #[cfg(target_os = "none")]
    { 0x08a0_9f8c as *const u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of!(HOST_DMA_ADDRESS) }
}

#[inline(always)]
unsafe fn rearm(base: *mut u32, saved_dma: *const u32) {
    base.add(4).write_volatile(0x6008_0040);
    let dma = saved_dma.read_volatile();
    base.add(5).write_volatile(dma & 0x7fff_ffff);
    let control = base.read_volatile();
    base.write_volatile(control | 0x8800_0000);
}

/// # Safety
/// Controller MMIO and the saved DMA word must be accessible, and access
/// must be serialized (including the isolated host fixture).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usb_out_endpoint_zero_rearm() {
    rearm(registers(), saved_dma_address());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_dma_preserves_control_and_neighbor_registers() {
        for dma in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0x8a09_f8c0, u32::MAX] {
            for control in [0u32, 0x0800_0000, 0x8000_0000, 0x1357_2468, u32::MAX] {
                let mut bank = [0xdead_beef; 8];
                bank[0] = control;
                let mut expected = bank;
                expected[0] = control | 0x8800_0000;
                expected[4] = 0x6008_0040;
                expected[5] = dma & 0x7fff_ffff;
                unsafe { rearm(bank.as_mut_ptr(), &dma) };
                assert_eq!(bank, expected);
            }
        }
    }

    #[test]
    fn size_write_precedes_dma_read_when_source_aliases_size() {
        let mut bank = [0x1234_5678; 8];
        let base = bank.as_mut_ptr();
        unsafe { rearm(base, base.add(4)) };
        assert_eq!(bank[5], 0x6008_0040);
        assert_eq!(bank[0], 0x9a34_5678);
    }
}

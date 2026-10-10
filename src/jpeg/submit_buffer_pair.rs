//! JPEG hardware buffer-pair submission — `FUN_0809bb88` @ 0x0809bb88.
//!
//! True extent [0x0809bb88, 0x0809bc70): 232 bytes, comprising 212
//! instruction bytes and five literals. The next function starts with PUSH.
//! Independent aligned raw-word decoding finds two plain incoming BLs
//! (0x08089f40, 0x0808a0cc), no predicated incoming BLs, and no outgoing
//! BLs of either kind. Clear the decoder completion byte, program the buffer
//! extent and both banks, select a bank into two 20-byte descriptors, wait
//! for hardware readiness, issue both commands, then XOR the selector with 1.
//! Register meanings beyond these observed operations remain unidentified.
//! Deliberate deviations: volatile accesses preserve device ordering; hosts
//! substitute isolated storage for fixed RAM/MMIO. All fields remain u32
//! words on hosts; arithmetic wraps exactly as ARM ADD/LSL does.

use core::ptr::{read_volatile, write_volatile};

#[cfg(not(target_os = "none"))]
pub static mut HOST_DECODER_STATE: [u32; 23] = [0; 23];
#[cfg(not(target_os = "none"))]
pub static mut HOST_BUFFER_REGISTERS: [u32; 16] = [0; 16];
#[cfg(not(target_os = "none"))]
pub static mut HOST_BANK_REGISTERS: [u32; 6] = [0; 6];
#[cfg(not(target_os = "none"))]
pub static mut HOST_COMMAND_REGISTERS: [u32; 0x1180c / 4] = [0; 0x1180c / 4];

/// Submit two adjacent five-word descriptors to the JPEG hardware.
///
/// # Safety
/// `buffers` must expose seven aligned readable words; `descriptors` must
/// expose ten aligned readable/writable words. Fixed state and MMIO must be
/// accessible. Host callers must serialize accesses to the stand-in storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn jpeg_submit_buffer_pair(buffers: *const u32, descriptors: *mut u32) {
    #[cfg(target_os = "none")]
    let (state, buffer_regs, bank_regs, command_regs) = (
        0x08a0_a79c as *mut u32, 0x3966_0000 as *mut u32,
        0x3965_0000 as *mut u32, 0x3963_0000 as *mut u32,
    );
    #[cfg(not(target_os = "none"))]
    let (state, buffer_regs, bank_regs, command_regs) = (
        core::ptr::addr_of_mut!(HOST_DECODER_STATE).cast::<u32>(),
        core::ptr::addr_of_mut!(HOST_BUFFER_REGISTERS).cast::<u32>(),
        core::ptr::addr_of_mut!(HOST_BANK_REGISTERS).cast::<u32>(),
        core::ptr::addr_of_mut!(HOST_COMMAND_REGISTERS).cast::<u32>(),
    );
    write_volatile(state.cast::<u8>(), 0);
    write_volatile(buffer_regs.add(6), read_volatile(descriptors.add(3)));
    write_volatile(buffer_regs.add(7), read_volatile(descriptors.add(3)).wrapping_add(0x200));
    write_volatile(buffer_regs.add(3), 3);
    write_volatile(buffer_regs.add(11), read_volatile(buffers.add(5)));
    write_volatile(buffer_regs.add(15), read_volatile(buffers.add(6)));
    let selector = read_volatile(state.add(22));
    let selected = read_volatile(buffers.add(if selector == 0 { 5 } else { 6 }));
    write_volatile(descriptors.add(4), selected);
    write_volatile(descriptors.add(9), selected.wrapping_add(8));
    while read_volatile(bank_regs.add(5)) & 0x10000 != 0 {}
    write_volatile(bank_regs.add(3), (selector << 30) | 0x80);
    for index in 0..2 {
        let enabled = (read_volatile(descriptors.add(index * 5)) != 0) as u32;
        while read_volatile(command_regs.add(0x11808 / 4)) & 2 != 0 {}
        write_volatile(command_regs.add(0x11800 / 4), 0x20341 | (enabled << 19));
        write_volatile(command_regs.add(0x10c / 4), 0x31 | (enabled << 3));
    }
    write_volatile(state.add(22), selector ^ 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banks_descriptors_wrapping_and_nonboolean_selectors() {
        unsafe {
            for selector in [0u32, 1, 2, 3, 0x8000_0000, u32::MAX] {
                for flags in [[0, 0], [1, 0], [0, 0x8000_0000], [u32::MAX, 7]] {
                    HOST_DECODER_STATE = [0xa5a5_a5a5; 23];
                    HOST_DECODER_STATE[22] = selector;
                    HOST_BUFFER_REGISTERS = [0xcccc_cccc; 16];
                    HOST_BANK_REGISTERS = [0xdddd_dddd; 6];
                    HOST_BANK_REGISTERS[5] = 0x8000_0001;
                    HOST_COMMAND_REGISTERS = [0xeeee_eeee; 0x1180c / 4];
                    HOST_COMMAND_REGISTERS[0x11808 / 4] = 0x8000_0001;
                    let buffers = [11, 12, 13, 14, 15, 0xffff_fffc, 0x1234_5678];
                    let mut descriptors = [flags[0], 21, 22, 0xffff_ff80, 24,
                                           flags[1], 26, 27, 28, 29];
                    jpeg_submit_buffer_pair(buffers.as_ptr(), descriptors.as_mut_ptr());
                    let selected = if selector == 0 { buffers[5] } else { buffers[6] };
                    assert_eq!(descriptors, [flags[0], 21, 22, 0xffff_ff80, selected,
                                            flags[1], 26, 27, 28, selected.wrapping_add(8)]);
                    let mut state = [0xa5a5_a5a5; 23];
                    state[0] = 0xa5a5_a500;
                    state[22] = selector ^ 1;
                    assert_eq!(read_volatile(core::ptr::addr_of!(HOST_DECODER_STATE)), state);
                    let mut regs = [0xcccc_cccc; 16];
                    regs[3] = 3;
                    regs[6] = 0xffff_ff80;
                    regs[7] = 0x180;
                    regs[11] = buffers[5];
                    regs[15] = buffers[6];
                    assert_eq!(read_volatile(core::ptr::addr_of!(HOST_BUFFER_REGISTERS)), regs);
                    let mut bank = [0xdddd_dddd; 6];
                    bank[3] = (selector << 30) | 0x80;
                    bank[5] = 0x8000_0001;
                    assert_eq!(read_volatile(core::ptr::addr_of!(HOST_BANK_REGISTERS)), bank);
                    let enabled = (flags[1] != 0) as u32;
                    let commands = core::ptr::addr_of!(HOST_COMMAND_REGISTERS).cast::<u32>();
                    for index in 0..0x1180c / 4 {
                        let expected = match index {
                            67 => 0x31 | (enabled << 3),
                            17920 => 0x20341 | (enabled << 19),
                            17922 => 0x8000_0001,
                            _ => 0xeeee_eeee,
                        };
                        assert_eq!(read_volatile(commands.add(index)), expected, "word {index}");
                    }
                    jpeg_submit_buffer_pair(buffers.as_ptr(), descriptors.as_mut_ptr());
                    assert_eq!(read_volatile(core::ptr::addr_of!(HOST_DECODER_STATE).cast::<u32>().add(22)), selector);
                    let next = if selector ^ 1 == 0 { buffers[5] } else { buffers[6] };
                    assert_eq!(descriptors[4], next);
                    assert_eq!(descriptors[9], next.wrapping_add(8));
                }
            }
        }
    }
}

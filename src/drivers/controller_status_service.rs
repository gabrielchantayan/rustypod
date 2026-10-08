//! Controller status acknowledgement and residual-status accumulation.
//!
//! Original: `FUN_08107110` @ `0x08107110`, true size 168 bytes:
//! 152 instruction bytes and four literals, next function at 0x081071b8.
//! Raw A32 scan: two plain inbound BLs, zero predicated inbound BLs;
//! two plain outbound BLs (0x08107dd8, 0x08107f1c), zero predicated BLs.
//! Mask register +4 with 0x000e0304 and write only when nonzero. Mask
//! status +0x14 with 0x5320e45f; return if zero. For bit 6, call the two
//! stock routines in order when context byte +0x2b is zero, then acknowledge
//! bit 6. Acknowledge bit 1 and mask 0xa408 separately, write residual bits,
//! and OR them into the shared word at 0x08a09f9c.
//!
//! Deviations: volatile aligned MMIO and shared-word accesses preserve raw
//! access ordering (Ghidra incorrectly drops intermediate status writes).
//! Unported callees have no ledger identities; retain their verified stock
//! addresses. Host entry requires hardware and panics; tests model register
//! accesses through the same algorithm, including write-one-to-clear status.

#[cfg(any(target_os = "none", test))]
use core::ptr;

#[cfg(any(target_os = "none", test))]
#[inline(always)]
unsafe fn service_with(
    context: *mut u8,
    mut read: impl FnMut(usize) -> u32,
    mut write: impl FnMut(usize, u32),
    mut recover: impl FnMut(*mut u8),
) {
    let masked = read(4) & 0x000e_0304;
    if masked != 0 { write(4, masked); }
    let mut pending = read(0x14) & 0x5320_e45f;
    if pending == 0 { return; }
    if pending & 0x40 != 0 {
        if context.add(0x2b).read() == 0 { recover(context); }
        write(0x14, 0x40);
        pending &= !0x40;
    }
    if pending & 2 != 0 {
        write(0x14, 2);
        pending &= !2;
    }
    let acknowledged = pending & 0xa408;
    if acknowledged != 0 {
        write(0x14, acknowledged);
        pending &= !acknowledged;
    }
    write(0x14, pending);
    let accumulated = read(0x24);
    write(0x24, accumulated | pending);
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_status_service(context: *mut u8) {
    #[cfg(target_os = "none")]
    service_with(context,
        |offset| ptr::read_volatile(register(offset)),
        |offset, value| ptr::write_volatile(register(offset), value),
        |output| {
            let first: unsafe extern "C" fn(*mut u8, u32) = core::mem::transmute(0x0810_7dd8usize);
            let second: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0810_7f1cusize);
            first(output, 1);
            second(output);
        });
    #[cfg(not(target_os = "none"))]
    {
        let _ = context;
        panic!("controller_status_service requires retail controller MMIO");
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
fn register(offset: usize) -> *mut u32 {
    if offset == 0x24 { 0x08a0_9f9c as *mut u32 }
    else { (0x3840_0000 + offset) as *mut u32 }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{cell::RefCell, vec::Vec};

    #[derive(Debug, PartialEq)]
    enum Access { Read(usize), Write(usize, u32), Recover }

    fn run(control: u32, status: u32, accumulator: u32, disabled: u8)
        -> (Vec<Access>, [u32; 3])
    {
        let words = RefCell::new([control, status, accumulator]);
        let accesses = RefCell::new(Vec::new());
        let mut context = [0u8; 0x2c];
        context[0x2b] = disabled;
        unsafe { service_with(context.as_mut_ptr(),
            |offset| {
                accesses.borrow_mut().push(Access::Read(offset));
                words.borrow()[if offset == 4 { 0 } else if offset == 0x14 { 1 } else { 2 }]
            },
            |offset, value| {
                accesses.borrow_mut().push(Access::Write(offset, value));
                let mut words = words.borrow_mut();
                if offset == 0x14 { words[1] &= !value; }
                else { words[if offset == 4 { 0 } else { 2 }] = value; }
            },
            |_| {
                accesses.borrow_mut().push(Access::Recover);
                // Stock recovery can alter registers; pending remains the snapshot,
                // while the accumulator is read only after recovery.
                words.borrow_mut()[1] |= 0x8000_0000;
                words.borrow_mut()[2] |= 0x2000_0000;
            }); }
        (accesses.into_inner(), words.into_inner())
    }

    #[test]
    fn zero_masked_status_does_not_touch_context_or_accumulator() {
        let mut reads = Vec::new();
        unsafe { service_with(ptr::null_mut(), |offset| {
            reads.push(offset);
            if offset == 4 { 0xfff1_fcfb_u32 } else { 0xacdf_1ba0 }
        }, |_, _| panic!("unexpected write"), |_| panic!("unexpected recovery")); }
        assert_eq!(reads, [4, 0x14]);
    }

    #[test]
    fn acknowledges_each_class_and_accumulates_only_residual_snapshot() {
        use Access::*;
        let (accesses, words) = run(u32::MAX, u32::MAX, 0x80, 0);
        assert_eq!(accesses, [Read(4), Write(4, 0xe0304), Read(0x14), Recover,
            Write(0x14, 0x40), Write(0x14, 2), Write(0x14, 0xa408),
            Write(0x14, 0x5320_4015), Read(0x24), Write(0x24, 0x7320_4095)]);
        assert_eq!(words, [0xe0304, 0xacdf_1ba0, 0x7320_4095]);
    }

    #[test]
    fn disabled_recovery_still_acknowledges_and_writes_zero_residual() {
        use Access::*;
        for disabled in [1, 0x80, 0xff] {
            let (accesses, words) = run(0, 0x40, 0x1234, disabled);
            assert_eq!(accesses, [Read(4), Read(0x14), Write(0x14, 0x40),
                Write(0x14, 0), Read(0x24), Write(0x24, 0x1234)]);
            assert_eq!(words, [0, 0, 0x1234]);
        }
    }

    #[test]
    fn each_status_bit_preserves_unselected_bits() {
        for bit in 0..32 {
            let status = 1u32 << bit;
            let (accesses, words) = run(0, status, 0x8000_0000, 1);
            let selected = status & 0x5320_e45f;
            let residual = selected & !(0x40 | 2 | 0xa408);
            assert_eq!(words, [0, status & !selected, 0x8000_0000 | residual]);
            assert_eq!(accesses.iter().any(|a| *a == Access::Read(0x24)), selected != 0);
        }
    }
}

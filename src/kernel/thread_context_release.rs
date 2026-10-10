//! Final-reference cleanup of the retail thread context.

use crate::runtime::malloc_rt::free;

/// thread_context_release — original: FUN_080b8300 @ 0x080b8300.
/// True extent: 116 bytes, ending before the independent push at 0x080b8374.
/// Raw A32 decoding verifies three plain outbound BLs, zero predicated BLs,
/// a tail B to free, and two plain inbound BLs (0x080cdf08, 0x082e820c).
/// Decrement +0x188 modulo 2^32 between CPSR control writes 0x93 and 0x13.
/// Only the transition to zero cleans up: unless flag +0x200 bit 3 is set,
/// free and clear the buffer at +0x208; delete the class-4 slot at +0x22c,
/// run kernel_slot_create on +0x228, clear +0x18c and +0, then free context.
/// Both kernel statuses are ignored, including failures.
///
/// Deliberate deviations: existing Rust ports replace the direct retail calls
/// and final tail branch. Host builds omit privileged CPSR writes. The existing
/// kernel_slot_create port uses a native usize slot; hosts copy the target u32
/// selector into a native slot and copy its resulting value back. ARM passes
/// the original field address directly. No saved IRQ state is restored: the
/// original unconditionally opens IRQ and FIQ in SVC mode on every path.
///
/// # Safety
/// `context` must be aligned, writable through +0x22f, and on final release
/// accepted by free. The owned buffer and kernel slots must be valid for their
/// existing callees. No NULL guard or reference-count underflow guard exists.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn thread_context_release(context: *mut u32) {
    #[cfg(target_arch = "arm")]
    core::arch::asm!("msr CPSR_c, #0x93", options(nostack));
    let references = context.add(0x188 / 4);
    let remaining = references.read_volatile().wrapping_sub(1);
    references.write_volatile(remaining);
    #[cfg(target_arch = "arm")]
    core::arch::asm!("msr CPSR_c, #0x13", options(nostack));
    if remaining != 0 {
        return;
    }
    if context.add(0x200 / 4).read() & 8 == 0 {
        free(context.add(0x208 / 4).read() as usize as *mut u8);
        context.add(0x208 / 4).write(0);
    }
    let _ = crate::kernel::object4_slot_delete::kernel_object4_slot_delete(
        context.add(0x22c / 4),
    );
    let slot = context.add(0x228 / 4);
    #[cfg(target_pointer_width = "32")]
    let _ = crate::kernel::kernel_slot_create::kernel_slot_create(slot.cast());
    #[cfg(not(target_pointer_width = "32"))]
    {
        let mut selector = slot.read() as usize;
        let _ = crate::kernel::kernel_slot_create::kernel_slot_create(&mut selector);
        slot.write(selector as u32);
    }
    context.add(0x18c / 4).write_volatile(0);
    context.write_volatile(0);
    free(context.cast());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::malloc_rt::{HeapOps, HEAP_OPS};
    use core::ptr;
    use parking_lot::Mutex;
    use std::vec::Vec;

    static RELEASES: Mutex<Vec<(usize, u32, u32, u32)>> = Mutex::new(Vec::new());
    static mut CONTEXT: *mut u32 = ptr::null_mut();

    unsafe extern "C" fn observe_free(block: *mut u8) {
        RELEASES.lock().push((block as usize, CONTEXT.read(),
            CONTEXT.add(0x18c / 4).read(), CONTEXT.add(0x208 / 4).read()));
    }

    struct Restore(HeapOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(HEAP_OPS).write_volatile(self.0); }
        }
    }

    #[test]
    fn reference_boundaries_and_final_ownership_cleanup() {
        let _lock = crate::runtime::malloc_rt::tests::lock_ops();
        unsafe {
            let saved = ptr::addr_of!(HEAP_OPS).read_volatile();
            let _restore = Restore(saved);
            ptr::addr_of_mut!(HEAP_OPS).write_volatile(HeapOps { free: observe_free, ..saved });
            for count in [0u32, 1, 2, u32::MAX] {
                for flags in [0u32, 8, 0xffff_fff7, u32::MAX] {
                    for buffer in [0u32, 0x1234_5678] {
                        let mut context = [0xa5a5_a5a5u32; 0x230 / 4];
                        context[0x188 / 4] = count;
                        context[0x200 / 4] = flags;
                        context[0x208 / 4] = buffer;
                        // Real kernel ports reject zero slots; cleanup must still finish.
                        context[0x228 / 4] = 0;
                        context[0x22c / 4] = 0;
                        let before = context;
                        CONTEXT = context.as_mut_ptr();
                        RELEASES.lock().clear();
                        thread_context_release(CONTEXT);
                        let mut expected = before;
                        expected[0x188 / 4] = count.wrapping_sub(1);
                        let mut releases = Vec::new();
                        if count == 1 {
                            if flags & 8 == 0 {
                                if buffer != 0 {
                                    releases.push((buffer as usize, before[0],
                                        before[0x18c / 4], buffer));
                                }
                                expected[0x208 / 4] = 0;
                            }
                            expected[0] = 0;
                            expected[0x18c / 4] = 0;
                            releases.push((CONTEXT as usize, 0, 0, expected[0x208 / 4]));
                        }
                        assert_eq!(context, expected);
                        assert_eq!(*RELEASES.lock(), releases);
                    }
                }
            }
            CONTEXT = ptr::null_mut();
        }
    }
}

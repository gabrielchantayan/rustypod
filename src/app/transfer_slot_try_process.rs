//! `transfer_slot_try_process` — original: `FUN_081e476c` @ `0x081e476c`
//! (68 bytes; true extent `0x081e476c..0x081e47af`).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM words establish one outbound plain unconditional `bl` to the
//! unrecovered routine at `0x081e46b0` and no predicated outbound `bl` forms.
//! Three inbound direct plain `bl` sites occur in `FUN_081e5828`; no predicated
//! inbound call forms occur. For the selected 0x50-byte slot, a nonzero byte
//! at +0x1284 bypasses the routine. Otherwise the routine receives the word at
//! +0x125c and an output count; on failure this function restores +0x125c from
//! +0x1244, and on success returns 3.
//!
//! # Deliberate deviations
//!
//! `0x081e46b0` has no recovered semantic identity. Target builds call its
//! verified retailOS address; the host build has a narrow callback seam. The
//! raw caller passes an uninitialized stack word, but the callee's first store
//! zeros that output; Rust initializes it to zero without changing its observed
//! value at the call boundary.

/// ABI of the unported routine at `0x081e46b0`.
pub type TransferSlotProcess = unsafe extern "C" fn(*mut u8, u32, u32, *mut u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_transfer_slot_process(
    _context: *mut u8,
    _slot_index: u32,
    _source: u32,
    _transferred: *mut u32,
) -> u32 {
    0
}

/// Host seam for the unported retailOS target.
#[cfg(not(target_os = "none"))]
pub static mut TRANSFER_SLOT_PROCESS: TransferSlotProcess = missing_transfer_slot_process;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn transfer_slot_process_target() -> TransferSlotProcess {
    core::mem::transmute(0x081e_46b0usize)
}

/// Attempts to process a selected transfer slot and restores its saved source
/// word when the attempt fails or the slot is disabled.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn transfer_slot_try_process(context: *mut u8, slot_index: u32) -> u32 {
    const SLOT_SIZE: usize = 0x50;
    const SOURCE: usize = 0x125c;
    const SAVED_SOURCE: usize = 0x1244;
    const DISABLED: usize = 0x1284;

    let slot = unsafe { context.add(slot_index as usize * SLOT_SIZE) };
    if unsafe { slot.add(DISABLED).read() } == 0 {
        let source = unsafe { (slot.add(SOURCE) as *const u32).read() };
        let mut transferred = 0;
        #[cfg(target_os = "none")]
        let result = unsafe { transfer_slot_process_target()(context, slot_index, source, &mut transferred) };
        #[cfg(not(target_os = "none"))]
        let result = unsafe { TRANSFER_SLOT_PROCESS(context, slot_index, source, &mut transferred) };
        if result != 0 {
            return 3;
        }
    }

    unsafe { (slot.add(SOURCE) as *mut u32).write((slot.add(SAVED_SOURCE) as *const u32).read()) };
    0
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALLS: usize = 0;
    static mut RESULT: u32 = 0;
    static mut ARGS: (usize, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn process(context: *mut u8, slot_index: u32, source: u32, transferred: *mut u32) -> u32 {
        unsafe {
            CALLS += 1;
            ARGS = (context as usize, slot_index, source);
            transferred.write(0x31);
            RESULT
        }
    }

    #[test]
    fn failed_or_disabled_slot_restores_saved_source() {
        let _guard = TEST_LOCK.lock();
        let mut context = [0u8; 0x1400];
        let slot_index = 2usize;
        let slot = slot_index * 0x50;
        unsafe {
            CALLS = 0;
            RESULT = 0;
            TRANSFER_SLOT_PROCESS = process;
            ((context.as_mut_ptr().add(slot + 0x1244)) as *mut u32).write(0x1122_3344);
            ((context.as_mut_ptr().add(slot + 0x125c)) as *mut u32).write(0xaabb_ccdd);
        }

        assert_eq!(unsafe { transfer_slot_try_process(context.as_mut_ptr(), slot_index as u32) }, 0);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(ARGS, (context.as_ptr() as usize, slot_index as u32, 0xaabb_ccdd));
            assert_eq!(((context.as_ptr().add(slot + 0x125c)) as *const u32).read(), 0x1122_3344);
        }

        context[slot + 0x1284] = 1;
        unsafe { ((context.as_mut_ptr().add(slot + 0x125c)) as *mut u32).write(0x5566_7788) };
        assert_eq!(unsafe { transfer_slot_try_process(context.as_mut_ptr(), slot_index as u32) }, 0);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(((context.as_ptr().add(slot + 0x125c)) as *const u32).read(), 0x1122_3344);
        }
    }

    #[test]
    fn successful_slot_reports_three_without_restoring_source() {
        let _guard = TEST_LOCK.lock();
        let mut context = [0u8; 0x1400];
        unsafe {
            CALLS = 0;
            RESULT = 1;
            TRANSFER_SLOT_PROCESS = process;
            ((context.as_mut_ptr().add(0x125c)) as *mut u32).write(0xdead_beef);
            ((context.as_mut_ptr().add(0x1244)) as *mut u32).write(0xfeed_face);
        }

        assert_eq!(unsafe { transfer_slot_try_process(context.as_mut_ptr(), 0) }, 3);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(((context.as_ptr().add(0x125c)) as *const u32).read(), 0xdead_beef);
        }
    }
}

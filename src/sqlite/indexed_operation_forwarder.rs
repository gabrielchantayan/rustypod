//! Indexed operation forwarding wrapper.
//!
//! `indexed_operation_forwarder` — original: `FUN_083653cc` @ **0x083653cc**
//! (**28 bytes**, `0x083653cc..0x083653e7`; the next separately linked
//! function begins at `0x083653e8` with `push {r4,r5,r6,lr}`). Whole-image
//! A32 decoding finds **two inbound plain `bl` call sites** (0x082c62a4 and
//! 0x082c6344), no predicated `bl` call sites, and one outbound plain `bl` to
//! the still-unclassified `FUN_082c63c8` at 0x082c63c8.
//!
//! # Algorithm
//!
//! This is an ABI forwarding wrapper: it preserves all five `u32` arguments,
//! including the fifth stack argument, calls `FUN_082c63c8`, and returns that
//! callee's status unchanged.
//!
//! # Deliberate deviations
//!
//! `FUN_082c63c8` has no verified semantic identity in `names.yaml`. Target
//! builds call its verified retail address; host tests install a recorder in a
//! volatile seam. The Rust source expresses the ARM stack-argument shuffle as
//! a normal five-argument call.

/// Still-stock `FUN_082c63c8`, the forwarded indexed operation.
pub const INDEXED_OPERATION_ADDRESS: usize = 0x082c_63c8;

/// ABI of the forwarded retail operation.
pub type IndexedOperation = unsafe extern "C" fn(u32, u32, u32, u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_indexed_operation(
    index: u32,
    argument: u32,
    third: u32,
    fourth: u32,
    mode: u32,
) -> u32 {
    let operation: IndexedOperation = unsafe { core::mem::transmute(INDEXED_OPERATION_ADDRESS) };
    unsafe { operation(index, argument, third, fourth, mode) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_indexed_operation(_: u32, _: u32, _: u32, _: u32, _: u32) -> u32 {
    panic!("indexed_operation_forwarder requires FUN_082c63c8 @ 0x082c63c8")
}

/// Target default preserves the retail `bl 0x082c63c8` behavior.
pub static mut INDEXED_OPERATION: IndexedOperation = retail_indexed_operation;

/// Volatile dispatch prevents LLVM from folding the target default away.
#[inline(always)]
unsafe fn indexed_operation() -> IndexedOperation {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(INDEXED_OPERATION)) }
}

/// Forward five ABI words to the still-stock indexed operation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_operation_forwarder(
    index: u32,
    argument: u32,
    third: u32,
    fourth: u32,
    mode: u32,
) -> u32 {
    let status = unsafe { indexed_operation()(index, argument, third, fourth, mode) };
    unsafe { core::ptr::read_volatile(&status) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED_ARGUMENTS: [u32; 5] = [0; 5];
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn record_indexed_operation(
        index: u32,
        argument: u32,
        third: u32,
        fourth: u32,
        mode: u32,
    ) -> u32 {
        unsafe {
            OBSERVED_ARGUMENTS = [index, argument, third, fourth, mode];
            CALLS += 1;
        }
        0xfeed_beef
    }

    #[test]
    fn forwards_every_abi_word_and_status() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            INDEXED_OPERATION = record_indexed_operation;
            OBSERVED_ARGUMENTS = [0; 5];
            CALLS = 0;
            assert_eq!(
                indexed_operation_forwarder(0, u32::MAX, 0x1234_5678, 4, 1),
                0xfeed_beef
            );
            assert_eq!(OBSERVED_ARGUMENTS, [0, u32::MAX, 0x1234_5678, 4, 1]);
            assert_eq!(CALLS, 1);
            INDEXED_OPERATION = retail_indexed_operation;
        }
    }
}

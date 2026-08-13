//! Six-word operation-dispatch wrapper — `operation_dispatch` @ 0x0802ad10.
//!
//! Original: `FUN_0802ad10` @ 0x0802ad10 (40 bytes).
//!
//! The ARM wrapper saves its incoming fifth and sixth stack arguments while
//! making room for the outgoing call, restores the six-word ABI expected by
//! the operation-dispatch core at 0x0802ac90, then returns that core's status
//! in `r0`. It does not inspect, alter, or retain any argument.

/// Observed ABI of the unported operation-dispatch core at 0x0802ac90.
pub type OperationDispatchCore = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_operation_dispatch_core(
    first: u32,
    second: u32,
    third: u32,
    operation: u32,
    fifth: u32,
    sixth: u32,
) -> i32 {
    let core: OperationDispatchCore = unsafe { core::mem::transmute(0x0802_ac90usize) };
    unsafe { core(first, second, third, operation, fifth, sixth) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_operation_dispatch_core(
    _first: u32,
    _second: u32,
    _third: u32,
    _operation: u32,
    _fifth: u32,
    _sixth: u32,
) -> i32 {
    panic!("operation_dispatch requires core 0x0802ac90")
}

#[cfg(target_os = "none")]
const DEFAULT_OPERATION_DISPATCH_CORE: OperationDispatchCore = firmware_operation_dispatch_core;
#[cfg(not(target_os = "none"))]
const DEFAULT_OPERATION_DISPATCH_CORE: OperationDispatchCore = missing_operation_dispatch_core;

/// The unported retailOS operation-dispatch core. Target builds call the ROM
/// entry directly; host tests replace this seam with a recorder.
pub static mut OPERATION_DISPATCH_CORE: OperationDispatchCore = DEFAULT_OPERATION_DISPATCH_CORE;

/// operation_dispatch — original: `FUN_0802ad10` @ 0x0802ad10 (40 bytes).
///
/// Forwards all six incoming words to the operation-dispatch core at
/// 0x0802ac90, preserving their order, and returns its status unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn operation_dispatch(
    first: u32,
    second: u32,
    third: u32,
    operation: u32,
    fifth: u32,
    sixth: u32,
) -> i32 {
    let core = unsafe { core::ptr::addr_of_mut!(OPERATION_DISPATCH_CORE).read_volatile() };
    unsafe { core(first, second, third, operation, fifth, sixth) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static CORE_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVED: [u32; 6] = [0; 6];

    unsafe extern "C" fn recording_operation_dispatch_core(
        first: u32,
        second: u32,
        third: u32,
        operation: u32,
        fifth: u32,
        sixth: u32,
    ) -> i32 {
        unsafe {
            RECEIVED = [first, second, third, operation, fifth, sixth];
        }
        -37
    }

    struct CoreReset;

    impl Drop for CoreReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(OPERATION_DISPATCH_CORE)
                    .write_volatile(DEFAULT_OPERATION_DISPATCH_CORE);
            }
        }
    }

    #[test]
    fn forwards_all_six_words_in_order_and_returns_core_status() {
        let _lock = CORE_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(RECEIVED).write([0; 6]);
            core::ptr::addr_of_mut!(OPERATION_DISPATCH_CORE)
                .write_volatile(recording_operation_dispatch_core);
        }
        let _reset = CoreReset;

        let status = unsafe {
            operation_dispatch(
                0x0102_0304,
                0x1112_1314,
                0x2122_2324,
                0x3132_3334,
                0x4142_4344,
                0x5152_5354,
            )
        };

        assert_eq!(status, -37);
        assert_eq!(
            unsafe { core::ptr::addr_of!(RECEIVED).read() },
            [
                0x0102_0304,
                0x1112_1314,
                0x2122_2324,
                0x3132_3334,
                0x4142_4344,
                0x5152_5354,
            ]
        );
    }
}

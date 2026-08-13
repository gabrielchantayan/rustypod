//! `h264_decode_forwarder` — original: `FUN_0802ac10` @ `0x0802ac10`
//! (40 bytes).
//!
//! # Algorithm
//!
//! This is the six-word ABI adapter immediately before the H.264 CBC decode
//! body at `0x0802ab90`. It preserves all six incoming words and calls that
//! body with them in their original order. The stock ARM saves `r2`, `r3`, and
//! the two stack arguments while it makes room for the callee's stack slots;
//! the wrapper itself has no result, so the decode body's status is discarded.
//!
//! The decode body is not ported. On hardware, the target seam invokes its
//! retailOS load address; host tests install a recording seam to prove the
//! complete six-argument call ABI.

/// ABI of the H.264 CBC decode body at retailOS address `0x0802ab90`.
pub type H264DecodeBody = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32) -> u32;

/// RetailOS load address of the six-argument H.264 decode body.
pub const H264_DECODE_BODY_ADDRESS: usize = 0x0802_ab90;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_h264_decode_body(
    arg1: u32,
    arg2: u32,
    arg3: u32,
    arg4: u32,
    arg5: u32,
    arg6: u32,
) -> u32 {
    let body: H264DecodeBody = core::mem::transmute(H264_DECODE_BODY_ADDRESS);
    body(arg1, arg2, arg3, arg4, arg5, arg6)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_h264_decode_body(
    _arg1: u32,
    _arg2: u32,
    _arg3: u32,
    _arg4: u32,
    _arg5: u32,
    _arg6: u32,
) -> u32 {
    panic!("h264_decode_forwarder requires decode body 0x0802ab90")
}

/// Active boundary for the unported H.264 decode body. On the target it calls
/// directly into retailOS; host tests replace it with a recording implementation.
#[cfg(target_os = "none")]
pub static mut H264_DECODE_BODY: H264DecodeBody = retail_h264_decode_body;

/// Active host boundary for the unported H.264 decode body.
#[cfg(not(target_os = "none"))]
pub static mut H264_DECODE_BODY: H264DecodeBody = missing_h264_decode_body;

#[inline(always)]
unsafe fn h264_decode_body() -> H264DecodeBody {
    core::ptr::read_volatile(core::ptr::addr_of!(H264_DECODE_BODY))
}

/// h264_decode_forwarder — original: `FUN_0802ac10` @ `0x0802ac10` (40 bytes).
///
/// Forwards six 32-bit decode words, in order, to the CBC decode body at
/// `0x0802ab90`; as in the stock `void` wrapper, its callee's status is
/// intentionally discarded.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn h264_decode_forwarder(
    arg1: u32,
    arg2: u32,
    arg3: u32,
    arg4: u32,
    arg5: u32,
    arg6: u32,
) {
    let _ = h264_decode_body()(arg1, arg2, arg3, arg4, arg5, arg6);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static FORWARDER_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVED: [u32; 6] = [0; 6];
    static mut RETURN_VALUE: u32 = 0;
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn recording_h264_decode_body(
        arg1: u32,
        arg2: u32,
        arg3: u32,
        arg4: u32,
        arg5: u32,
        arg6: u32,
    ) -> u32 {
        RECEIVED = [arg1, arg2, arg3, arg4, arg5, arg6];
        CALLS += 1;
        RETURN_VALUE
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                H264_DECODE_BODY = missing_h264_decode_body;
                RECEIVED = [0; 6];
                RETURN_VALUE = 0;
                CALLS = 0;
            }
        }
    }

    #[test]
    fn forwards_all_six_words_in_order_and_discards_the_decode_status() {
        let _lock = FORWARDER_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        let arguments = [0x10u32, 0x21, 0x32, 0x43, 0x54, 0x65];
        unsafe {
            H264_DECODE_BODY = recording_h264_decode_body;
            RETURN_VALUE = 0xfeed_beef;
            h264_decode_forwarder(
                arguments[0],
                arguments[1],
                arguments[2],
                arguments[3],
                arguments[4],
                arguments[5],
            );
            assert_eq!(CALLS, 1, "the wrapper makes one decode-body call");
            assert_eq!(RECEIVED, arguments, "all register and stack words retain their order");
        }
    }
}

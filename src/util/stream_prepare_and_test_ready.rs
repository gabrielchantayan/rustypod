//! Original: `FUN_083d81ac` @ `0x083d81ac` (96 bytes).
//!
//! Raw words `e92d4010 e1a04000 e1a00001 e5911000 e511100c e0811000
//! e5911004 e3110a01 0a000002 e3520000 03a01004 0a000000 e3a01000
//! e3811010 eb000008 e5901000 e511100c e0810000 e5900010 e2700001
//! 33a00000 e5c40000 e1a00004 e8bd8010` establish the exact A32 body from
//! `0x083d81ac` through `0x083d820b`; the push at `0x083d820c` starts the
//! next real function. The body has one outgoing unconditional plain `bl`, at
//! `0x083d81e4` to still-unported `FUN_083d820c`, and no predicated `bl`.
//! Whole-image A32 branch decoding finds two inbound unconditional plain `bl`
//! sites (`0x083b5458`, `0x083d8150`) and no predicated inbound calls.
//!
//! Algorithm: select call flags `0x10` or `0x14` from the stream state bit
//! `0x1000` and `force_prepare`, call the unported preparation helper, then
//! store whether its resulting state word at `+0x10` is zero. Deliberate
//! deviation: the unresolved direct callee is a verified-address call on the
//! target and an injectable host seam; host stream fields use native-width
//! vtable pointers rather than the target's four-byte words.

const STREAM_STATE_OFFSET_FROM_VTABLE: usize = 12;
const STREAM_ACTIVITY_FLAG_OFFSET: usize = 4;
const STREAM_RESULT_OFFSET: usize = 0x10;
const UNPORTED_DIRECT_HELPER_ADDRESS: usize = 0x083d_820c;

type DirectHelper = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn stream_state_base(stream: *mut u8) -> *mut u8 {
    let vtable = unsafe { stream.cast::<u32>().read_volatile() as *const u8 };
    let offset = unsafe { vtable.sub(STREAM_STATE_OFFSET_FROM_VTABLE).cast::<i32>().read_volatile() };
    unsafe { stream.offset(offset as isize) }
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostStreamVtable {
    pub state_offset: isize,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostStream {
    pub vtable: *const HostStreamVtable,
    pub activity_flag: u32,
    pub result: u32,
}

unsafe extern "C" fn missing_direct_helper(_stream: *mut u8, _flags: u32) -> *mut u8 {
    panic!("stream_prepare_and_test_ready requires a direct-helper seam")
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct StreamPrepareAndTestReadyOps {
    pub call: DirectHelper,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_STREAM_PREPARE_AND_TEST_READY_OPS: StreamPrepareAndTestReadyOps = StreamPrepareAndTestReadyOps {
    call: missing_direct_helper,
};

#[cfg(not(target_os = "none"))]
pub static mut STREAM_PREPARE_AND_TEST_READY_OPS: StreamPrepareAndTestReadyOps = DEFAULT_STREAM_PREPARE_AND_TEST_READY_OPS;

/// # Safety
/// `result` must be writable and `stream` must satisfy the retail stream
/// layout through its vtable-relative `+0x10` state word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_prepare_and_test_ready(result: *mut u8, stream: *mut u8, force_prepare: u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    let state = unsafe { stream_state_base(stream) };
    #[cfg(target_os = "none")]
    let activity_flag = unsafe { state.add(STREAM_ACTIVITY_FLAG_OFFSET).cast::<u32>().read_volatile() };
    #[cfg(not(target_os = "none"))]
    let activity_flag = unsafe { stream.cast::<HostStream>().read().activity_flag };
    let flags = if activity_flag & 0x1000 != 0 && force_prepare == 0 { 0x14 } else { 0x10 };
    #[cfg(target_os = "none")]
    let prepared = unsafe { core::mem::transmute::<usize, DirectHelper>(UNPORTED_DIRECT_HELPER_ADDRESS)(stream, flags) };
    #[cfg(not(target_os = "none"))]
    let prepared = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_PREPARE_AND_TEST_READY_OPS.call))(stream, flags) };

    #[cfg(target_os = "none")]
    let is_ready = unsafe { stream_state_base(prepared).add(STREAM_RESULT_OFFSET).cast::<u32>().read_volatile() == 0 };
    #[cfg(not(target_os = "none"))]
    let is_ready = unsafe { prepared.cast::<HostStream>().read().result == 0 };
    unsafe { result.write(is_ready as u8) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut FLAGS: u32 = 0;
    static mut PREPARED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn prepare(_stream: *mut u8, flags: u32) -> *mut u8 {
        unsafe { FLAGS = flags; PREPARED }
    }

    #[test]
    fn flagged_non_forced_prepare_uses_flag_14_and_reports_zero_result() {
        let _lock = LOCK.lock();
        let vtable = HostStreamVtable { state_offset: 0 };
        let mut stream = HostStream { vtable: &vtable, activity_flag: 0x1000, result: 0 };
        unsafe {
            FLAGS = 0;
            PREPARED = (&mut stream as *mut HostStream).cast();
            STREAM_PREPARE_AND_TEST_READY_OPS = StreamPrepareAndTestReadyOps { call: prepare };
            let mut result = 0xff;
            assert_eq!(stream_prepare_and_test_ready(&mut result, (&mut stream as *mut HostStream).cast(), 0), &mut result as *mut u8);
            assert_eq!((FLAGS, result), (0x14, 1));
        }
    }

    #[test]
    fn forced_prepare_uses_flag_10_and_rejects_nonzero_result() {
        let _lock = LOCK.lock();
        let vtable = HostStreamVtable { state_offset: 0 };
        let mut stream = HostStream { vtable: &vtable, activity_flag: 0x1000, result: 2 };
        unsafe {
            FLAGS = 0;
            PREPARED = (&mut stream as *mut HostStream).cast();
            STREAM_PREPARE_AND_TEST_READY_OPS = StreamPrepareAndTestReadyOps { call: prepare };
            let mut result = 0xff;
            stream_prepare_and_test_ready(&mut result, (&mut stream as *mut HostStream).cast(), 1);
            assert_eq!((FLAGS, result), (0x10, 0));
        }
    }
}

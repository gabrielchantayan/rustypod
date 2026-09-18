//! Closes a buffered stream state — `FUN_081618bc` @ 0x081618bc.
//!
//! Raw `osos.dec` establishes the exact 56-byte extent from 0x081618bc
//! through `pop {r4,r5,pc}` at 0x081618f0; 0x081618f4 starts the next real
//! function. The body makes one plain direct `bl` (0x0816179c) and one
//! predicated indirect `blxne` through the stream vtable's +4 slot.
//!
//! Algorithm: finalize pending stream data, release the stream through its
//! virtual slot +4 when present, clear the target-width stream word at +4 and
//! the active byte at +0x18, then return the finalizer status. Deliberate
//! deviation: 0x0816179c has no recovered identity, so it is exposed as a
//! role-based finalizer seam on hosts and called at its verified retail
//! address on target builds. Host stream and vtable fields are widened to
//! preserve their roles without truncating function pointers.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_BUFFERED_STREAM_FINALIZE: usize = 0x0816_179c;

#[cfg(target_os = "none")]
#[repr(C)]
pub struct BufferedStreamCloseState {
    pub unresolved_00: u32,
    pub stream: u32,
    pub unresolved_08_to_14: [u32; 4],
    pub active: u8,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct BufferedStreamCloseState {
    pub unresolved_00: u32,
    pub stream: *mut HostBufferedStream,
    pub unresolved_08_to_14: [u32; 4],
    pub active: u8,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostBufferedStreamVtable {
    pub unresolved_00: usize,
    pub release: unsafe extern "C" fn(*mut HostBufferedStream),
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostBufferedStream {
    pub vtable: *const HostBufferedStreamVtable,
}

pub type BufferedStreamFinalize = unsafe extern "C" fn(*mut BufferedStreamCloseState) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct BufferedStreamCloseOps {
    pub finalize: BufferedStreamFinalize,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_buffered_stream_finalize(_state: *mut BufferedStreamCloseState) -> u32 {
    panic!("install buffered-stream close host operations before closing a stream")
}

#[cfg(not(target_os = "none"))]
pub static mut BUFFERED_STREAM_CLOSE_OPS: BufferedStreamCloseOps = BufferedStreamCloseOps {
    finalize: missing_buffered_stream_finalize,
};

#[inline(always)]
unsafe fn finalize(state: *mut BufferedStreamCloseState) -> u32 {
    #[cfg(target_os = "none")]
    {
        let finalizer: BufferedStreamFinalize = unsafe { core::mem::transmute(RETAIL_BUFFERED_STREAM_FINALIZE) };
        unsafe { finalizer(state) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let finalizer = unsafe { core::ptr::read_volatile(addr_of!(BUFFERED_STREAM_CLOSE_OPS.finalize)) };
        unsafe { finalizer(state) }
    }
}

/// Finalizes and releases the state-owned buffered stream.
///
/// # Safety
///
/// `state` must be valid for the target-layout fields. Its non-null `stream`
/// must name an object with a valid vtable release slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buffered_stream_close(state: *mut BufferedStreamCloseState) -> u32 {
    let result = unsafe { finalize(state) };

    #[cfg(target_os = "none")]
    {
        let stream = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*state).stream)) };
        if stream != 0 {
            let vtable = unsafe { core::ptr::read_volatile(stream as usize as *const u32) };
            let release_address = unsafe { core::ptr::read_volatile((vtable as usize as *const u32).add(1)) };
            let release: unsafe extern "C" fn(u32) = unsafe { core::mem::transmute(release_address as usize) };
            unsafe { release(stream) };
        }
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).stream), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).active), 0);
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let stream = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*state).stream)) };
        if !stream.is_null() {
            let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*stream).vtable)) };
            unsafe { ((*vtable).release)(stream) };
        }
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).stream), core::ptr::null_mut());
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*state).active), 0);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut FINALIZE_RESULT: u32 = 0;
    static mut FINALIZE_STATE: *mut BufferedStreamCloseState = core::ptr::null_mut();
    static mut RELEASED_STREAM: *mut HostBufferedStream = core::ptr::null_mut();

    unsafe extern "C" fn record_finalize(state: *mut BufferedStreamCloseState) -> u32 {
        unsafe {
            FINALIZE_STATE = state;
            FINALIZE_RESULT
        }
    }

    unsafe extern "C" fn record_release(stream: *mut HostBufferedStream) {
        unsafe { RELEASED_STREAM = stream };
    }

    #[test]
    fn finalizes_releases_and_clears_owned_stream() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            BUFFERED_STREAM_CLOSE_OPS = BufferedStreamCloseOps { finalize: record_finalize };
            FINALIZE_RESULT = 0x42;
            FINALIZE_STATE = core::ptr::null_mut();
            RELEASED_STREAM = core::ptr::null_mut();
        }
        let vtable = HostBufferedStreamVtable { unresolved_00: 0, release: record_release };
        let mut stream = HostBufferedStream { vtable: &vtable };
        let mut state = BufferedStreamCloseState {
            unresolved_00: 0,
            stream: &mut stream,
            unresolved_08_to_14: [0; 4],
            active: 1,
        };

        assert_eq!(unsafe { buffered_stream_close(&mut state) }, 0x42);
        assert!(core::ptr::eq(unsafe { FINALIZE_STATE }, &mut state));
        assert!(core::ptr::eq(unsafe { RELEASED_STREAM }, &mut stream));
        assert!(state.stream.is_null());
        assert_eq!(state.active, 0);
    }

    #[test]
    fn clears_inactive_state_without_virtual_release() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            BUFFERED_STREAM_CLOSE_OPS = BufferedStreamCloseOps { finalize: record_finalize };
            FINALIZE_RESULT = 7;
            RELEASED_STREAM = core::ptr::null_mut();
        }
        let mut state = BufferedStreamCloseState {
            unresolved_00: 0,
            stream: core::ptr::null_mut(),
            unresolved_08_to_14: [0; 4],
            active: 0xff,
        };

        assert_eq!(unsafe { buffered_stream_close(&mut state) }, 7);
        assert!(unsafe { RELEASED_STREAM }.is_null());
        assert!(state.stream.is_null());
        assert_eq!(state.active, 0);
    }
}

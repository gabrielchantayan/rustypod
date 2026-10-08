//! Scoped stream-write dispatch — FUN_08121538 @ 0x08121538.
//!
//! Raw extent [0x08121538, 0x081215c8): 144 bytes, no literals.
//! Whole-image A32 decoding: zero plain and two predicated inbound BLs
//! (0x081e58f0, 0x08206918); body: three plain BLs, zero predicated BLs,
//! and three BLX-register calls. The next function begins at 0x081215c8.
//! Construct a 0x114-byte stack owner with capacity 1024, publish it in the
//! context, and open through owner slot +8. On failure destroy and return 1.
//! Otherwise dispatch context slot +8 with both payload words, close through
//! the reloaded context owner slot +12, destroy the original stack owner,
//! and return the dispatch result. The published pointer is not cleared.
//! Deviations: native pointer fields/slots on hosts, and host callbacks for
//! the fixed firmware owner vtable; target dispatch uses the original table.

use super::stream_write_owner_construct::{stream_write_owner_construct, StreamWriteOwnerPrefix};
use super::stream_write_owner_destroy::stream_write_owner_destroy;
use core::mem::MaybeUninit;

type OwnerMethod = unsafe extern "C" fn(*mut u32) -> u32;
type WriteMethod = unsafe extern "C" fn(*mut StreamWriteContext, u32, u32) -> u32;

#[repr(C)]
pub struct StreamWriteContext {
    pub vtable: *const usize,
    pub owner: *mut u32,
}

#[cfg(not(target_os = "none"))]
pub static mut OWNER_OPEN: Option<OwnerMethod> = None;
#[cfg(not(target_os = "none"))]
pub static mut OWNER_CLOSE: Option<OwnerMethod> = None;

unsafe fn owner_method(owner: *mut u32, slot: usize) -> u32 {
    #[cfg(target_os = "none")]
    let method: OwnerMethod = core::mem::transmute((owner.read() as usize as *const usize).add(slot).read());
    #[cfg(not(target_os = "none"))]
    let method = if slot == 2 { OWNER_OPEN.expect("owner open not installed") }
        else { OWNER_CLOSE.expect("owner close not installed") };
    method(owner)
}

/// Safety: valid context/vtable, callable slot +8, and a NUL-terminated name
/// fitting the owner's 256-byte inline buffer. Callbacks must not retain the
/// stack owner beyond this invocation; the original leaves its pointer stale.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_write_scoped(
    context: *mut StreamWriteContext, name: *const u8, first: u32, second: u32,
) -> u32 {
    let mut storage = MaybeUninit::<[u32; 69]>::uninit();
    let owner = storage.as_mut_ptr().cast::<u32>();
    stream_write_owner_construct(owner.cast::<StreamWriteOwnerPrefix>(), name, 1024, 1);
    core::ptr::addr_of_mut!((*context).owner).write(owner);
    if owner_method(owner, 2) != 0 {
        stream_write_owner_destroy(owner);
        return 1;
    }
    let write: WriteMethod = core::mem::transmute((*context).vtable.add(2).read());
    let result = write(context, first, second);
    owner_method(core::ptr::addr_of!((*context).owner).read(), 3);
    stream_write_owner_destroy(owner);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    struct State { open_result: u32, write_result: u32, events: std::vec::Vec<u8>, original: usize, replace: usize }
    static STATE: Mutex<State> = Mutex::new(State { open_result: 0, write_result: 0, events: std::vec::Vec::new(), original: 0, replace: 0 });
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn open(owner: *mut u32) -> u32 {
        let mut state = STATE.lock();
        state.events.push(1);
        state.original = owner as usize;
        assert_eq!(owner.add(1).read(), 0);
        assert_eq!(owner.add(2).read(), 0);
        assert_eq!(owner.add(67).read(), 1024);
        assert_eq!(core::slice::from_raw_parts(owner.add(3).cast::<u8>(), 5), b"test\0");
        state.open_result
    }
    unsafe extern "C" fn write(context: *mut StreamWriteContext, first: u32, second: u32) -> u32 {
        let mut state = STATE.lock();
        state.events.push(2);
        assert_eq!((first, second), (0x12345678, 0xabcdef01));
        assert_eq!((*context).owner as usize, state.original);
        if state.replace != 0 { (*context).owner = state.replace as *mut u32; }
        state.write_result
    }
    unsafe extern "C" fn close(owner: *mut u32) -> u32 {
        let mut state = STATE.lock();
        state.events.push(3);
        assert_eq!(owner as usize, if state.replace == 0 { state.original } else { state.replace });
        0xffff_ffff // Close status is deliberately ignored.
    }

    #[test]
    fn open_failures_normalize_and_skip_write_and_close() {
        let _guard = TEST_LOCK.lock();
        unsafe { OWNER_OPEN = Some(open); OWNER_CLOSE = Some(close); }
        for status in [1, 34, 0x8000_0000, u32::MAX] {
            *STATE.lock() = State { open_result: status, write_result: 0, events: std::vec::Vec::new(), original: 0, replace: 0 };
            let mut context = StreamWriteContext { vtable: core::ptr::null(), owner: core::ptr::null_mut() };
            assert_eq!(unsafe { stream_write_scoped(&mut context, b"test\0".as_ptr(), 0x12345678, 0xabcdef01) }, 1);
            let state = STATE.lock();
            assert_eq!(state.events, [1]);
            assert_eq!(context.owner as usize, state.original);
        }
    }

    #[test]
    fn preserves_dispatch_status_and_closes_reloaded_owner() {
        let _guard = TEST_LOCK.lock();
        unsafe { OWNER_OPEN = Some(open); OWNER_CLOSE = Some(close); }
        let vtable = [0usize, 0, write as usize];
        let mut replacement = [0u32; 69];
        for replace in [0, replacement.as_mut_ptr() as usize] {
            for result in [0, 1, 0x8000_0000, u32::MAX] {
                *STATE.lock() = State { open_result: 0, write_result: result, events: std::vec::Vec::new(), original: 0, replace };
                let mut context = StreamWriteContext { vtable: vtable.as_ptr(), owner: core::ptr::null_mut() };
                assert_eq!(unsafe { stream_write_scoped(&mut context, b"test\0".as_ptr(), 0x12345678, 0xabcdef01) }, result);
                let state = STATE.lock();
                assert_eq!(state.events, [1, 2, 3]);
                assert_eq!(context.owner as usize, if replace == 0 { state.original } else { replace });
                assert_eq!(replacement, [0; 69]);
            }
        }
    }
}

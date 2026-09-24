//! Playback-position selection.
//!
//! `playback_position_get` — original: `FUN_08113408` @ `0x08113408`
//! (48 bytes; true extent `0x08113408..0x08113438`; the next function starts
//! with `add r0, r0, #0x38` at `0x08113438`). A full raw-image A32 branch decode
//! finds three direct, unconditional inbound `bl` instructions (0x081125e8,
//! 0x081f42a0, and 0x082118c4), with no predicated `bl` callers.
//!
//! Algorithm: return the cached position at `+0x528` while its validity byte at
//! `+0x52c` is set. Otherwise, return the fallback position at `+0x51c` when
//! the pending byte at `+0x51a` is set; when clear, tail-dispatch the opaque
//! playback object's vtable slot `+0x17c`, using the object stored at `+0x888`.
//! The virtual method remains deliberately unnamed because its identity is not
//! established by the slot. Deliberate deviation: the ARM tail `bxeq` is a
//! normal Rust return; host builds use an ABI seam because target vtable words
//! contain 32-bit function addresses while host function pointers are wider.

const FALLBACK_POSITION_OFFSET: usize = 0x51c;
const CACHED_POSITION_OFFSET: usize = 0x528;
const CACHED_POSITION_VALID_OFFSET: usize = 0x52c;
const PENDING_OFFSET: usize = 0x51a;
const PLAYBACK_OBJECT_OFFSET: usize = 0x888;
const PLAYBACK_POSITION_VTABLE_OFFSET: usize = 0x17c;

type PlaybackPositionQuery = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_playback_position_query(_object: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
pub static mut PLAYBACK_POSITION_QUERY: PlaybackPositionQuery = missing_playback_position_query;

#[cfg(target_os = "none")]
unsafe fn playback_position_query(object: *mut u8) -> u32 {
    let vtable = unsafe { object.cast::<u32>().read() as *const u8 };
    let query = unsafe {
        core::mem::transmute::<usize, PlaybackPositionQuery>(
            vtable.add(PLAYBACK_POSITION_VTABLE_OFFSET).cast::<u32>().read() as usize,
        )
    };
    unsafe { query(object) }
}

/// Returns the current playback position selected by the application's state.
///
/// # Safety
/// `state` must denote the unchecked retail object layout through `+0x88c`.
/// When neither cached nor pending state applies, its `+0x888` playback object
/// and that object's vtable slot `+0x17c` must be readable and callable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn playback_position_get(state: *mut u8) -> u32 {
    if unsafe { state.add(CACHED_POSITION_VALID_OFFSET).read() } != 0 {
        return unsafe { state.add(CACHED_POSITION_OFFSET).cast::<u32>().read() };
    }
    if unsafe { state.add(PENDING_OFFSET).read() } != 0 {
        return unsafe { state.add(FALLBACK_POSITION_OFFSET).cast::<u32>().read() };
    }

    let object = unsafe { state.add(PLAYBACK_OBJECT_OFFSET).cast::<u32>().read() as *mut u8 };
    #[cfg(target_os = "none")]
    return unsafe { playback_position_query(object) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PLAYBACK_POSITION_QUERY))(object) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut QUERY_RESULT: u32 = 0;
    static mut QUERY_CALLS: u32 = 0;
    static mut QUERY_OBJECT: usize = 0;

    unsafe extern "C" fn position_query(object: *mut u8) -> u32 {
        QUERY_CALLS += 1;
        QUERY_OBJECT = object as usize;
        QUERY_RESULT
    }

    fn state() -> [u8; PLAYBACK_OBJECT_OFFSET + 4] { [0; PLAYBACK_OBJECT_OFFSET + 4] }

    unsafe fn write_word(state: &mut [u8], offset: usize, value: u32) {
        state.as_mut_ptr().add(offset).cast::<u32>().write_unaligned(value);
    }

    unsafe fn install_query(result: u32) {
        PLAYBACK_POSITION_QUERY = position_query;
        QUERY_RESULT = result;
        QUERY_CALLS = 0;
        QUERY_OBJECT = 0;
    }

    #[test]
    fn cached_position_wins_without_virtual_query() {
        let _lock = TEST_LOCK.lock();
        let mut input = state();
        unsafe {
            install_query(0xdddd_dddd);
            write_word(&mut input, CACHED_POSITION_OFFSET, 0x1234_5678);
            input[CACHED_POSITION_VALID_OFFSET] = 1;
            input[PENDING_OFFSET] = 1;
            assert_eq!(playback_position_get(input.as_mut_ptr()), 0x1234_5678);
            assert_eq!(QUERY_CALLS, 0);
        }
    }

    #[test]
    fn pending_position_skips_virtual_query() {
        let _lock = TEST_LOCK.lock();
        let mut input = state();
        unsafe {
            install_query(0xdddd_dddd);
            write_word(&mut input, FALLBACK_POSITION_OFFSET, 0x8765_4321);
            input[PENDING_OFFSET] = 1;
            assert_eq!(playback_position_get(input.as_mut_ptr()), 0x8765_4321);
            assert_eq!(QUERY_CALLS, 0);
        }
    }

    #[test]
    fn clear_state_queries_playback_object() {
        let _lock = TEST_LOCK.lock();
        let mut input = state();
        unsafe {
            install_query(0x2468_ace0);
            write_word(&mut input, PLAYBACK_OBJECT_OFFSET, 0x1234_5000);
            assert_eq!(playback_position_get(input.as_mut_ptr()), 0x2468_ace0);
            assert_eq!(QUERY_CALLS, 1);
            assert_eq!(QUERY_OBJECT, 0x1234_5000);
        }
    }
}

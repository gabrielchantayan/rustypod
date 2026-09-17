//! Flushes the pending block of a buffered stream — `FUN_08277d1c` @
//! 0x08277d1c.
//!
//! Raw `osos.dec` establishes the exact 96-byte extent from 0x08277d1c
//! through `pop {r4,lr}; bx lr` at 0x08277d78; 0x08277d7c begins the next
//! sibling function. Whole-image A32 decoding finds four incoming plain `bl`
//! calls (0x08277ce4, 0x08277ec8, 0x082780e4, 0x08278be4) and no predicated
//! `bl` calls. The body itself makes one plain `bl`, to the unported
//! 0x08277dd4 helper, and no predicated calls.
//!
//! Algorithm: when both state bytes +4 and +5 are nonzero, multiply the block
//! index at +8 by the backing object's +0x2c block size. Flush that range,
//! capped at backing-object +0x20, through 0x08277dd4; then clear byte +5 and
//! return the helper status. Otherwise return zero without touching the state.
//! Deliberate deviation: the target's pointer fields remain u32 words on all
//! hosts, preserving their verified four-byte offsets. The unported helper has
//! no stronger recovered identity, so target builds call its fixed address and
//! host tests install a volatile ABI seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_BUFFERED_STREAM_FLUSH_BLOCK: usize = 0x0827_7dd4;

/// Target-width backing-object fields read by the flush wrapper.
#[repr(C)]
pub struct BufferedStreamBacking {
    pub unresolved_00_to_1c: [u32; 8],
    pub length: u32,
    pub unresolved_24_to_28: [u32; 2],
    pub block_size: u32,
}

/// Target-width state passed to the wrapper.
#[repr(C)]
pub struct BufferedStreamState {
    pub backing: u32,
    pub active: u8,
    pub pending: u8,
    pub unresolved_06: [u8; 2],
    pub block_index: u32,
    pub unresolved_0c: u32,
    pub flush_context: u32,
}

/// ABI of the unported block-flush helper at 0x08277dd4.
pub type BufferedStreamFlushBlock = unsafe extern "C" fn(
    *mut BufferedStreamState,
    u32,
    u32,
    *mut u32,
    u32,
) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct BufferedStreamFlushOps {
    pub flush_block: BufferedStreamFlushBlock,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_flush_block(
    _state: *mut BufferedStreamState,
    _offset: u32,
    _len: u32,
    _written: *mut u32,
    _context: u32,
) -> u32 {
    panic!("install buffered-stream flush host operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
pub static mut BUFFERED_STREAM_FLUSH_OPS: BufferedStreamFlushOps = BufferedStreamFlushOps {
    flush_block: missing_flush_block,
};

#[inline(always)]
unsafe fn flush_block(
    state: *mut BufferedStreamState,
    offset: u32,
    len: u32,
    written: *mut u32,
    context: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        let helper: BufferedStreamFlushBlock = unsafe { core::mem::transmute(RETAIL_BUFFERED_STREAM_FLUSH_BLOCK) };
        return unsafe { helper(state, offset, len, written, context) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let helper = unsafe { core::ptr::read_volatile(addr_of!(BUFFERED_STREAM_FLUSH_OPS.flush_block)) };
        unsafe { helper(state, offset, len, written, context) }
    }
}

/// Flushes the pending block when this buffered stream is active.
///
/// # Safety
///
/// `state` must be readable. When both state flags are nonzero, its `backing`
/// word must name a readable [`BufferedStreamBacking`] and the unported helper
/// must accept the exact target-layout state and arguments.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buffered_stream_flush_pending(state: *mut BufferedStreamState) -> u32 {
    if unsafe { (*state).active } == 0 || unsafe { (*state).pending } == 0 {
        return 0;
    }

    let backing = unsafe { ((*state).backing as usize) as *const BufferedStreamBacking };
    let block_size = unsafe { (*backing).block_size };
    let offset = block_size.wrapping_mul(unsafe { (*state).block_index });
    let length = unsafe { (*backing).length };
    let flush_len = if length <= block_size.wrapping_add(offset) {
        length.wrapping_sub(offset)
    } else {
        block_size
    };
    let mut written = 0;
    let result = unsafe { flush_block(state, offset, flush_len, &mut written, (*state).flush_context) };
    unsafe { (*state).pending = 0 };
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static BACKING: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BUFFERED_STREAM_FLUSH_PENDING, 0x1000).map(|p| p as usize)
    });
    static mut CALL: Option<(u32, u32, u32)> = None;
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn record_flush(
        _state: *mut BufferedStreamState,
        offset: u32,
        len: u32,
        written: *mut u32,
        context: u32,
    ) -> u32 {
        unsafe { CALL = Some((offset, len, context)) };
        unsafe { written.write(0x1234) };
        unsafe { RESULT }
    }

    fn state(backing: u32, active: u8, pending: u8, index: u32, context: u32) -> BufferedStreamState {
        BufferedStreamState { backing, active, pending, unresolved_06: [0; 2], block_index: index, unresolved_0c: 0, flush_context: context }
    }

    #[test]
    fn inactive_or_clean_state_does_not_dispatch() {
        let _guard = LOCK.lock();
        unsafe { CALL = None };
        let mut inactive = state(0, 0, 1, 0, 0);
        let mut clean = state(0, 1, 0, 0, 0);
        assert_eq!(unsafe { buffered_stream_flush_pending(addr_of_mut!(inactive)) }, 0);
        assert_eq!(unsafe { buffered_stream_flush_pending(addr_of_mut!(clean)) }, 0);
        assert_eq!(unsafe { CALL }, None);
        assert_eq!(inactive.pending, 1);
    }

    #[test]
    fn flushes_final_partial_block_and_clears_pending_on_error() {
        let _guard = LOCK.lock();
        let Some(backing) = *BACKING else {
            assert!(note_missing_u32_fixture("app/buffered_stream_flush_pending"));
            return;
        };
        let backing = backing as *mut BufferedStreamBacking;
        unsafe { backing.write(BufferedStreamBacking { unresolved_00_to_1c: [0; 8], length: 10, unresolved_24_to_28: [0; 2], block_size: 4 }) };
        unsafe { BUFFERED_STREAM_FLUSH_OPS.flush_block = record_flush; CALL = None; RESULT = 0x15 };
        let mut stream = state(backing as u32, 1, 1, 2, 0x88);
        assert_eq!(unsafe { buffered_stream_flush_pending(addr_of_mut!(stream)) }, 0x15);
        assert_eq!(unsafe { CALL }, Some((8, 2, 0x88)));
        assert_eq!(stream.pending, 0);
    }
}

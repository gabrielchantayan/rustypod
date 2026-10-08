//! Playback position without the separate +0x528 cache.
//!
//! Original `FUN_08111488` at `0x08111488`, true size **32 bytes** through
//! `0x081114a8`, where the next function starts with push {r4, lr}.
//! Raw A32 decoding verifies two inbound plain BLs (0x08114454, 0x08114de0),
//! zero predicated inbound BLs, zero outbound plain/predicated BLs and one
//! conditional BX virtual tail dispatch. Return +0x51c when pending byte
//! +0x51a is nonzero; otherwise query the playback interface at +0x888 via
//! vtable slot +0x17c. Both callers consume the full unsigned return word.
//! The existing playback_position_get uses this same selection after its
//! cache check; the concrete virtual method's identity remains unproven.
//!
//! Deliberate deviations: repr(C) native pointers widen on hosts, preserving
//! target field order and vtable word indices. Rust expresses conditional
//! instructions as a branch and tail dispatch as a returned call. No null
//! guards, result normalization or guessed fixed-address callee seams.

#[repr(C)]
pub struct PlaybackPositionVtable {
    pub reserved: [usize; 0x17c / 4],
    pub query: unsafe extern "C" fn(*mut PlaybackPositionInterface) -> u32,
}

#[repr(C)]
pub struct PlaybackPositionInterface {
    pub vtable: *const PlaybackPositionVtable,
}

#[repr(C)]
pub struct UncachedPlaybackPositionContext {
    pub reserved_000_519: [u8; 0x51a],
    pub pending: u8,
    pub reserved_51b: u8,
    pub pending_position: u32,
    pub reserved_520_887: [u32; (0x888 - 0x520) / 4],
    pub interface: *mut PlaybackPositionInterface,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x888] = [(); core::mem::offset_of!(UncachedPlaybackPositionContext, interface)];
const _: [(); 0x51a] = [(); core::mem::offset_of!(UncachedPlaybackPositionContext, pending)];
const _: [(); 0x51c] = [(); core::mem::offset_of!(UncachedPlaybackPositionContext, pending_position)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0x17c] = [(); core::mem::offset_of!(PlaybackPositionVtable, query)];

/// # Safety
/// Context fields must be readable and aligned. When pending is zero, the
/// interface and vtable must be valid and the query callable with its receiver.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn playback_position_uncached_get(context: *mut UncachedPlaybackPositionContext) -> u32 {
    if (*context).pending != 0 {
        return (*context).pending_position;
    }
    let interface = (*context).interface;
    ((*(*interface).vtable).query)(interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> UncachedPlaybackPositionContext {
        UncachedPlaybackPositionContext {
            reserved_000_519: [0x35; 0x51a], pending: 0, reserved_51b: 0x76,
            pending_position: 0, reserved_520_887: [0xaabbccdd; (0x888 - 0x520) / 4],
            interface: core::ptr::null_mut(),
        }
    }

    #[test]
    fn every_nonzero_pending_byte_returns_full_word_without_interface_access() {
        let mut context = context();
        for pending in 1..=u8::MAX {
            context.pending = pending;
            for value in [0, 1, 0x80000000, u32::MAX] {
                context.pending_position = value;
                assert_eq!(unsafe { playback_position_uncached_get(&mut context) }, value);
                assert_eq!(context.pending, pending);
                assert_eq!(context.pending_position, value);
            }
        }
        assert_eq!(context.reserved_000_519, [0x35; 0x51a]);
        assert_eq!(context.reserved_51b, 0x76);
        assert_eq!(context.reserved_520_887, [0xaabbccdd; (0x888 - 0x520) / 4]);
    }

    #[repr(C)]
    struct PositionState {
        interface: PlaybackPositionInterface,
        position: u32,
        calls: u32,
    }

    unsafe extern "C" fn advance(interface: *mut PlaybackPositionInterface) -> u32 {
        let state = &mut *interface.cast::<PositionState>();
        let result = state.position;
        state.position = result.wrapping_add(1);
        state.calls += 1;
        result
    }

    #[test]
    fn clear_pending_queries_receiver_and_transition_selects_pending_word() {
        let table = PlaybackPositionVtable { reserved: [0; 0x17c / 4], query: advance };
        let mut state = PositionState {
            interface: PlaybackPositionInterface { vtable: &table }, position: u32::MAX, calls: 0,
        };
        let mut context = context();
        context.interface = &mut state.interface;
        context.pending_position = 0x80000000;
        for expected in [u32::MAX, 0, 1] {
            assert_eq!(unsafe { playback_position_uncached_get(&mut context) }, expected);
            assert_eq!(state.position, expected.wrapping_add(1));
        }
        context.pending = 0x80;
        assert_eq!(unsafe { playback_position_uncached_get(&mut context) }, 0x80000000);
        assert_eq!(state.calls, 3);
        context.pending = 0;
        state.position = 0x80000000;
        assert_eq!(unsafe { playback_position_uncached_get(&mut context) }, 0x80000000);
        assert_eq!(state.calls, 4);
        assert_eq!(context.pending_position, 0x80000000);
        assert_eq!(context.reserved_000_519, [0x35; 0x51a]);
        assert_eq!(context.reserved_520_887, [0xaabbccdd; (0x888 - 0x520) / 4]);
    }
}

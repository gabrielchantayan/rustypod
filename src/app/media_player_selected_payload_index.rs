//! Media-player selected-payload index query — `FUN_08051c60` @ 0x08051c60.
//!
//! True extent [0x08051c60, 0x08051ce4): 132 bytes, ending in a branch to
//! the common epilogue; the next function starts with MOV r2,r0 at 0x08051ce4.
//! Raw A32 decoding finds five plain unconditional BLs, zero predicated BLs,
//! and two indirect BLXs (+0x1a4 gate and +0x15c context fill). Whole-image
//! decoding finds two incoming unconditional BLs and zero predicated BLs.
//!
//! Ignore the first argument, get the media-player singleton, construct a
//! zero-owner/mode context, and query the player's +0x1a4 gate. A nonzero gate
//! returns zero without filling the context. Otherwise fill it through +0x15c
//! and query object_selected_payload_index with the unchanged unsigned index.
//! Destroy the context on both paths and preserve the query result.
//!
//! Deliberate deviations: native pointer-sized vtable slots and ScopedContext
//! fields on hosts; host tests replace only the indexed payload operation,
//! whose target-width object layout cannot consume a native host context.
//! Target builds reuse all three existing ports without address-backed seams.

use core::{mem::MaybeUninit, ptr};
use super::scoped_context::{ScopedContext, scoped_context_construct, scoped_context_destroy};
use super::singletons::media_player_get;
#[cfg(target_os = "none")]
use crate::util::object_selected_payload_index::object_selected_payload_index;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_index_query(_: *mut u8, _: u32) -> u32 {
    panic!("install media-player indexed payload host operation")
}
#[cfg(not(target_os = "none"))]
pub static mut INDEX_QUERY: unsafe extern "C" fn(*mut u8, u32) -> u32 = missing_index_query;

/// # Safety
/// The singleton must have valid +0x1a4 and +0x15c virtual operations. A filled
/// context must satisfy object_selected_payload_index's unchecked contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_selected_payload_index(_object: *const u8, index: u32) -> u32 {
    let player = media_player_get();
    let mut context = MaybeUninit::<ScopedContext>::uninit();
    scoped_context_construct(context.as_mut_ptr(), ptr::null_mut(), 0);
    let vtable = player.cast::<*const usize>().read();
    let gate: unsafe extern "C" fn(*mut u8) -> u32 =
        core::mem::transmute(vtable.add(0x1a4 / 4).read());
    let result = if gate(player) != 0 {
        0
    } else {
        // Reload the vtable: the gate may change it.
        let vtable = player.cast::<*const usize>().read();
        let fill: unsafe extern "C" fn(*mut u8, *mut ScopedContext) =
            core::mem::transmute(vtable.add(0x15c / 4).read());
        fill(player, context.as_mut_ptr());
        #[cfg(target_os = "none")]
        let result = object_selected_payload_index(context.as_mut_ptr().cast(), index);
        #[cfg(not(target_os = "none"))]
        let result = ptr::read_volatile(ptr::addr_of!(INDEX_QUERY))(context.as_mut_ptr().cast(), index);
        result
    };
    scoped_context_destroy(context.as_mut_ptr());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::singletons::{MEDIA_PLAYER_INSTANCE, SINGLETON_LOCK};
    use super::super::scoped_context::SCOPED_CONTEXT_VTABLE;

    #[repr(C)]
    struct Player {
        vtable: *const usize,
        gate: u32,
        replacement: *const usize,
        values: [u32; 3],
    }

    unsafe extern "C" fn gate(player: *mut u8) -> u32 {
        let player = &mut *player.cast::<Player>();
        player.vtable = player.replacement;
        player.gate
    }
    unsafe extern "C" fn fill(player: *mut u8, context: *mut ScopedContext) {
        assert_eq!((*context).vtable, &SCOPED_CONTEXT_VTABLE as *const _);
        assert!((*context).owner.is_null());
        assert_eq!((*context).owner_valid, 0);
        assert_eq!((*context).mode, 0);
        (*context).owner = ptr::addr_of_mut!((*player.cast::<Player>()).values).cast();
    }
    unsafe extern "C" fn index_query(context: *mut u8, index: u32) -> u32 {
        let values = &*(*context.cast::<ScopedContext>()).owner.cast::<[u32; 3]>();
        values.get(index as usize).copied().unwrap_or(0)
    }

    #[test]
    fn gate_polarity_vtable_replacement_and_unsigned_index_boundaries() {
        let _singleton = SINGLETON_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _context = crate::testing::APP_ROOT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut slots = [0usize; 0x1a4 / 4 + 1];
        slots[0x1a4 / 4] = gate as *const () as usize;
        let mut replacement = slots;
        replacement[0x15c / 4] = fill as *const () as usize;
        let mut player = Player {
            vtable: slots.as_ptr(), gate: 0, replacement: replacement.as_ptr(),
            values: [0, 0x8000_0000, u32::MAX],
        };
        unsafe {
            let saved_player = MEDIA_PLAYER_INSTANCE;
            let saved_query = INDEX_QUERY;
            MEDIA_PLAYER_INSTANCE = ptr::addr_of_mut!(player).cast();
            INDEX_QUERY = index_query;
            for blocked in [1, 0x8000_0000, u32::MAX] {
                player.gate = blocked;
                player.vtable = slots.as_ptr();
                // Both tables have an invalid fill slot: a blocked gate must skip it.
                player.replacement = slots.as_ptr();
                assert_eq!(media_player_selected_payload_index(ptr::null(), u32::MAX), 0);
            }
            player.gate = 0;
            player.replacement = replacement.as_ptr();
            for (index, expected) in [(0, 0), (1, 0x8000_0000), (2, u32::MAX), (3, 0), (u32::MAX, 0)] {
                player.vtable = slots.as_ptr();
                assert_eq!(media_player_selected_payload_index(ptr::null(), index), expected);
            }
            INDEX_QUERY = saved_query;
            MEDIA_PLAYER_INSTANCE = saved_player;
        }
    }
}

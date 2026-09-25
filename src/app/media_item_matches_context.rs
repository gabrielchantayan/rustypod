//! Tests whether a media item's context identifier matches its selected record.
//!
//! `media_item_matches_context` — original: `FUN_0805352c` @ `0x0805352c`
//! (**196 bytes**, from the `stmdb sp!,{r4-r7,lr}` through the branch at
//! `0x080535ec`; the next real function starts at `0x080535f0`). Decoding the
//! raw ARM words finds **four plain unconditional `bl`** call sites
//! (0x0805356c, 0x08053598, 0x080535b8, and 0x080535e4), **zero predicated
//! `bl`** call sites, and two virtual `blx` calls through media-player slots
//! +0x190 and +0x15c.
//!
//! The function clears `matches`, rejects a null result pointer, negative
//! index, or index outside `object+0xef4` with -50, then asks the media player
//! for the current scoped-context identifier. If that identifier exists, it
//! compares it with the selected record's word at +0x10. Deliberate deviation:
//! host tests replace the two unresolved media-player virtual calls and the
//! scoped-context query with one native callback; target builds retain their
//! verified virtual ABI and the existing scoped-context constructor/destructor.

#[cfg(target_os = "none")]
use crate::app::scoped_context::{scoped_context_construct, scoped_context_destroy};
use crate::app::scoped_context::ScopedContext;
#[cfg(target_os = "none")]
use crate::app::singletons::media_player_get;
#[cfg(target_os = "none")]
use core::mem::MaybeUninit;

const ITEM_COUNT_OFFSET: usize = 0xef4;
const ITEM_TABLE_OFFSET: usize = 0xeec;
const ITEM_CONTEXT_ID_OFFSET: usize = 0x10;
const INVALID_ARGUMENT: i32 = -50;

#[repr(C)]
struct MediaPlayerVtable {
    _before_fill_context: [usize; 0x15c / 4],
    fill_context: unsafe extern "C" fn(*mut u8, *mut ScopedContext),
    _before_available: [usize; (0x190 - 0x160) / 4],
    context_available: unsafe extern "C" fn(*mut u8) -> u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x194] = [0; core::mem::size_of::<MediaPlayerVtable>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x190] = [0; core::mem::offset_of!(MediaPlayerVtable, context_available)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x15c] = [0; core::mem::offset_of!(MediaPlayerVtable, fill_context)];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn current_context_id() -> Option<u32> {
    let player = media_player_get();
    let vtable = (player as *const *const MediaPlayerVtable).read();
    if ((*vtable).context_available)(player) == 0 {
        return None;
    }
    let mut context = MaybeUninit::<ScopedContext>::uninit();
    scoped_context_construct(context.as_mut_ptr(), core::ptr::null_mut(), 0);
    ((*vtable).fill_context)(player, context.as_mut_ptr());
    let context_vtable = (context.as_ptr() as *const *const usize).read();
    let valid = core::mem::transmute::<usize, unsafe extern "C" fn(*mut ScopedContext) -> u32>(context_vtable.add(2).read());
    let id = if valid(context.as_mut_ptr()) != 0 {
        let owner = (context.as_ptr() as *const u32).add(1).read() as usize as *const u32;
        Some(owner.add(6).read())
    } else {
        None
    };
    scoped_context_destroy(context.as_mut_ptr());
    id
}

#[cfg(not(target_os = "none"))]
type CurrentContextId = unsafe extern "C" fn() -> Option<u32>;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_context_id() -> Option<u32> { None }
#[cfg(not(target_os = "none"))]
static mut CURRENT_CONTEXT_ID: CurrentContextId = unavailable_context_id;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn current_context_id() -> Option<u32> {
    core::ptr::read_volatile(core::ptr::addr_of!(CURRENT_CONTEXT_ID))()
}

/// # Safety
/// `object` must point to readable words at +0xeec/+0xef4. For an accepted
/// index, its table word must be a valid target-width pointer to a readable
/// record carrying a context identifier at +0x10. `matches` must be writable.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.media_item_matches_context")]
#[inline(never)]
pub unsafe extern "C" fn media_item_matches_context(object: *const u8, index: i32, matches: *mut u8) -> i32 {
    if matches.is_null() || index < 0 || (object.add(ITEM_COUNT_OFFSET).cast::<u32>().read() <= index as u32) {
        return INVALID_ARGUMENT;
    }
    matches.write(0);
    if let Some(context_id) = current_context_id() {
        let table = object.add(ITEM_TABLE_OFFSET).cast::<u32>().read() as usize as *const u32;
        let item = table.add(index as usize).read() as usize as *const u32;
        if item.add(ITEM_CONTEXT_ID_OFFSET / 4).read() == context_id {
            matches.write(1);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use std::sync::Mutex;

    const FIXTURE_LEN: usize = 0x2000;
    const TABLE_OFFSET: usize = 0x1000;
    const ITEM_OFFSET: usize = 0x1100;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONTEXT_ID: Option<u32> = None;

    unsafe extern "C" fn test_context_id() -> Option<u32> { CONTEXT_ID }

    fn install() -> std::sync::MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe { addr_of_mut!(CURRENT_CONTEXT_ID).write(test_context_id); }
        guard
    }

    #[test]
    fn rejects_invalid_arguments_without_touching_output() {
        let _guard = install();
        let Some(object) = try_map_u32_slab(hints::MEDIA_ITEM_MATCHES_CONTEXT, FIXTURE_LEN) else { return; };
        unsafe {
            object.write_bytes(0, FIXTURE_LEN);
            let mut result = 0xa5;
            assert_eq!(media_item_matches_context(object, -1, &mut result), INVALID_ARGUMENT);
            assert_eq!(result, 0xa5);
            assert_eq!(media_item_matches_context(object, 0, core::ptr::null_mut()), INVALID_ARGUMENT);
        }
    }

    #[test]
    fn clears_then_sets_only_matching_selected_item() {
        let _guard = install();
        let Some(object) = try_map_u32_slab(hints::MEDIA_ITEM_MATCHES_CONTEXT, FIXTURE_LEN) else { return; };
        unsafe {
            object.write_bytes(0, FIXTURE_LEN);
            object.add(ITEM_COUNT_OFFSET).cast::<u32>().write(2);
            object.add(ITEM_TABLE_OFFSET).cast::<u32>().write(object.add(TABLE_OFFSET) as usize as u32);
            object.add(TABLE_OFFSET).cast::<u32>().write(object.add(ITEM_OFFSET) as usize as u32);
            object.add(TABLE_OFFSET + 4).cast::<u32>().write(object.add(ITEM_OFFSET + 0x40) as usize as u32);
            object.add(ITEM_OFFSET + ITEM_CONTEXT_ID_OFFSET).cast::<u32>().write(0x1020_3040);
            object.add(ITEM_OFFSET + 0x40 + ITEM_CONTEXT_ID_OFFSET).cast::<u32>().write(0x5566_7788);
            CONTEXT_ID = Some(0x1020_3040);
            let mut result = 0xa5;
            assert_eq!(media_item_matches_context(object, 0, &mut result), 0);
            assert_eq!(result, 1);
            assert_eq!(media_item_matches_context(object, 1, &mut result), 0);
            assert_eq!(result, 0);
            CONTEXT_ID = None;
            result = 0xa5;
            assert_eq!(media_item_matches_context(object, 0, &mut result), 0);
            assert_eq!(result, 0);
            addr_of_mut!(CURRENT_CONTEXT_ID).write(unavailable_context_id);
        }
    }
}

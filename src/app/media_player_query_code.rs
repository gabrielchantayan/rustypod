//! Priority media-player query, `FUN_08051c1c` @ **0x08051c1c**.
//! True extent [0x08051c1c, 0x08051c60), **68 bytes**; next entry is PUSH.
//! Raw A32 words verify two incoming plain BLs (0x081115fc, 0x08114670),
//! zero predicated callers; one outgoing plain BL, zero predicated BLs,
//! and two register BLX instructions. Acquire media_player_get, return 1
//! if virtual slot 100 is nonzero; otherwise reload the vtable and return
//! 2 if slot 101 is nonzero, else 0. No playback-state meaning is inferred.
//! Deviations: native pointer-sized vtable entries on hosts, retaining slot
//! indices. Reuse the existing singleton (including its documented constructor
//! and cache limitations); this port does not make that dependency hook-ready.

use super::singletons::media_player_get;
type Query = unsafe extern "C" fn(*mut u8) -> u32;

/// # Safety
/// The singleton must be a live object with readable vtable slot 100 and,
/// after that call returns zero, a readable, callable slot 101.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_query_code() -> u32 {
    let player = media_player_get();
    let table = player.cast::<*const Query>().read();
    if table.add(100).read()(player) != 0 {
        return 1;
    }
    let table = player.cast::<*const Query>().read();
    if table.add(101).read()(player) != 0 { 2 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::singletons::{MEDIA_PLAYER_INSTANCE, SINGLETON_LOCK};

    #[repr(C)]
    struct Player {
        table: *const Query,
        replacement: *const Query,
        first: u32,
        second: u32,
        calls: [u32; 2],
    }
    unsafe extern "C" fn first(player: *mut u8) -> u32 {
        let p = &mut *player.cast::<Player>();
        p.calls[0] += 1;
        p.table = p.replacement;
        p.first
    }
    unsafe extern "C" fn second(player: *mut u8) -> u32 {
        let p = &mut *player.cast::<Player>();
        p.calls[1] += 1;
        p.second
    }
    unsafe extern "C" fn stale(_: *mut u8) -> u32 {
        panic!("second query used stale vtable")
    }
    #[test]
    fn priority_nonzero_boundaries_and_vtable_reload() {
        let _guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved = core::ptr::addr_of!(MEDIA_PLAYER_INSTANCE).read();
            let mut initial = [stale as Query; 102];
            initial[100] = first;
            let mut replacement = [stale as Query; 102];
            replacement[101] = second;
            for a in [0, 1, 0x8000_0000, u32::MAX] {
                for b in [0, 1, 0x8000_0000, u32::MAX] {
                    let mut player = Player { table: initial.as_ptr(),
                        replacement: replacement.as_ptr(), first: a, second: b, calls: [0; 2] };
                    core::ptr::addr_of_mut!(MEDIA_PLAYER_INSTANCE).write((&mut player as *mut Player).cast());
                    assert_eq!(media_player_query_code(), if a != 0 { 1 } else if b != 0 { 2 } else { 0 });
                    assert_eq!(player.calls, [1, (a == 0) as u32]);
                }
            }
            core::ptr::addr_of_mut!(MEDIA_PLAYER_INSTANCE).write(saved);
        }
    }
}

//! Lazy match-key initialization for an entry cursor.

use crate::app::entry_match_first::entry_match_first;

#[repr(C)]
pub struct EntryCursorVtable {
    pub prepare: unsafe extern "C" fn(*mut EntryCursor) -> u32,
}

/// Verified prefix only; retailOS callers also use fields beyond this prefix.
#[repr(C)]
pub struct EntryCursor {
    pub vtable: *const EntryCursorVtable,
    pub container: *const u8,
    pub reserved: u32,
    pub match_key: u32,
}

/// Original: FUN_081a8d5c @ 0x081a8d5c, 84 bytes, ending at the next
/// independent push at 0x081a8db0. Whole-image raw A32 decoding verifies
/// two plain inbound BLs (0x081a8bf0, 0x081a8dc0), zero predicated BLs.
/// The body has one plain BL to entry_match_first and one BLX through
/// vtable slot zero. Always invoke that slot. On success, retain a nonzero
/// cached key; otherwise fetch the first entry and copy its +8 word if it
/// exists. Return whether the final cached key is nonzero, including when
/// preparation fails. Read fields after dispatch because it may mutate them.
/// Deliberate deviations: call the existing Rust entry_match_first port;
/// repr(C) native pointers permit host dispatch without truncation while
/// preserving the four-byte pointer fields and +0x0c key on ARM.
///
/// # Safety
/// The cursor and slot-zero vtable must be valid; the callback must preserve
/// a valid cursor. Its container must meet entry_match_first's contract.
/// Any nonzero first-entry word must address aligned storage readable through
/// +0x0b. Callback mutation must not invalidate the cursor or its storage.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn entry_cursor_ensure_key(cursor: *mut EntryCursor) -> u32 {
    let prepare = unsafe { (*(*cursor).vtable).prepare };
    if unsafe { prepare(cursor) } != 0 && unsafe { (*cursor).match_key } == 0 {
        let entry = unsafe { entry_match_first((*cursor).container) };
        if entry != 0 {
            unsafe {
                (*cursor).match_key = (entry as usize as *const u32).add(2).read();
            }
        }
    }
    (unsafe { (*cursor).match_key } != 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    unsafe extern "C" fn prepare(cursor: *mut EntryCursor) -> u32 {
        unsafe { (*cursor).reserved += 1; }
        1
    }
    unsafe extern "C" fn reject(cursor: *mut EntryCursor) -> u32 {
        unsafe { (*cursor).reserved += 1; }
        0
    }
    unsafe extern "C" fn replace_key(cursor: *mut EntryCursor) -> u32 {
        unsafe { (*cursor).match_key = 0x8000_0000; }
        0
    }
    fn cursor(callback: unsafe extern "C" fn(*mut EntryCursor) -> u32, key: u32) -> (EntryCursorVtable, EntryCursor) {
        (EntryCursorVtable { prepare: callback }, EntryCursor {
            vtable: core::ptr::null(), container: core::ptr::null(),
            reserved: 0, match_key: key,
        })
    }

    #[test]
    fn dispatch_always_runs_and_failed_preparation_preserves_cached_key() {
        for callback in [prepare as unsafe extern "C" fn(*mut EntryCursor) -> u32, reject] {
            for key in [0, 1, 0x8000_0000, u32::MAX] {
                let (vtable, mut object) = cursor(callback, key);
                object.vtable = &vtable;
                assert_eq!(unsafe { entry_cursor_ensure_key(&mut object) }, (key != 0) as u32);
                assert_eq!(object.match_key, key);
                assert_eq!(object.reserved, 1);
            }
        }
    }

    #[test]
    fn failed_callback_can_supply_the_final_key() {
        let (vtable, mut object) = cursor(replace_key, 0);
        object.vtable = &vtable;
        assert_eq!(unsafe { entry_cursor_ensure_key(&mut object) }, 1);
        assert_eq!(object.match_key, 0x8000_0000);
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::ENTRY_CURSOR_ENSURE_KEY, 4096)
            .map(|p| p as usize)
    });

    #[test]
    fn first_entry_key_is_cached_only_after_success_and_retried_when_zero() {
        let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(base) = *SLAB else {
            assert!(crate::testing::note_missing_u32_fixture("app::entry_cursor_ensure_key"));
            return;
        };
        unsafe {
            let container = (base + 0x100) as *mut u32;
            let nested = (base + 0x200) as *mut u32;
            let entry = (base + 0x300) as *mut u32;
            core::ptr::write_bytes(base as *mut u8, 0, 4096);
            container.add(2).write(nested as usize as u32);
            nested.write(0x6974_696c);
            container.add(9).write(entry as usize as u32);
            let (vtable, mut object) = cursor(prepare, 0);
            object.vtable = &vtable;
            object.container = container.cast();
            assert_eq!(entry_cursor_ensure_key(&mut object), 0);
            entry.add(2).write(u32::MAX);
            assert_eq!(entry_cursor_ensure_key(&mut object), 1);
            assert_eq!(object.match_key, u32::MAX);
            entry.add(2).write(42);
            assert_eq!(entry_cursor_ensure_key(&mut object), 1);
            assert_eq!(object.match_key, u32::MAX);
            object.match_key = 0;
            let rejected = EntryCursorVtable { prepare: reject };
            object.vtable = &rejected;
            assert_eq!(entry_cursor_ensure_key(&mut object), 0);
            assert_eq!(object.match_key, 0);
            object.vtable = &vtable;
            assert_eq!(entry_cursor_ensure_key(&mut object), 1);
            assert_eq!(object.match_key, 42);
            object.match_key = 0;
            container.add(9).write(0);
            assert_eq!(entry_cursor_ensure_key(&mut object), 0);
            assert_eq!(object.match_key, 0);
        }
    }
}

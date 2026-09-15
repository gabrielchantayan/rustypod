//! Dispatches a media-player snapshot through an opaque handle-owned callback.
//!
//! `scoped_string_id_record_set_dispatch` — original: `FUN_08177d2c` @
//! **0x08177d2c** (**220 bytes**, from the prologue through `pop {r4-r6,pc}`
//! at 0x08177e04; the next separately linked function begins at 0x08177e08).
//! Raw ARM decoding finds **12 plain, unconditional `bl` instructions** and
//! **zero predicated `bl` instructions**; the two indirect calls are `blx r2`
//! and `blx r3`. It constructs two ScopedStringIdRecordSets, snapshots the
//! media player's scalar + five StringIdRecord members at +0x9e8..+0xa48 into
//! the first, lets virtual slot +0x1f8 populate the second, then calls the
//! returned object's slot zero with `(first, second, 1)`. Both temporaries are
//! destroyed in reverse construction order.
//!
//! Deliberate deviations: the opaque virtual and callback targets remain named
//! by their proven slots, not an invented class or operation. Host builds use
//! replaceable operations because retailOS's 32-bit vtable words cannot hold
//! host function pointers.

use crate::app::scoped_string_id_record_set::{
    scoped_string_id_record_set_construct, scoped_string_id_record_set_destroy,
    ScopedStringIdRecordSet,
};
use crate::app::singletons::media_player_get;
use crate::cxx::handle::handle_deref_or_null;
use crate::cxx::string_object::string_id_record_assign;
use core::mem::MaybeUninit;

const PLAYER_RECORDS_OFFSET: usize = 0x9f8;
const PLAYER_TRAILING_WORD_OFFSET: usize = 0xa48;
const POPULATE_SNAPSHOT_VTABLE_WORD: usize = 0x1f8 / 4;

type PopulateSnapshot = unsafe extern "C" fn(*mut u8, *mut ScopedStringIdRecordSet) -> *mut u8;
type SnapshotCallback = unsafe extern "C" fn(
    *mut u8,
    *mut ScopedStringIdRecordSet,
    *mut ScopedStringIdRecordSet,
    u32,
) -> u32;

/// scoped_string_id_record_set_dispatch — original: `FUN_08177d2c` @
/// 0x08177d2c (220 bytes; 12 unconditional direct `bl`, no predicated `bl`).
///
/// Constructs source and destination record sets, copies the media-player
/// fields into source, invokes the opaque handle object's vtable slot +0x1f8,
/// then invokes slot zero of its return value. There is no NULL guard.
///
/// # Safety
///
/// `callback_handle` must point to the retail two-level handle layout; every
/// opaque target and the media-player singleton must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_string_id_record_set_dispatch(
    callback_handle: *const *const *mut u8,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        let mut source = MaybeUninit::<ScopedStringIdRecordSet>::uninit();
        let mut destination = MaybeUninit::<ScopedStringIdRecordSet>::uninit();
        let source = scoped_string_id_record_set_construct(source.as_mut_ptr());
        let destination = scoped_string_id_record_set_construct(destination.as_mut_ptr());
        let player = media_player_get();
        let source_bytes = source.cast::<u8>();

        source_bytes.add(0x08).cast::<u32>().write(player.add(0x9e8).cast::<u32>().read());
        source_bytes.add(0x0c).cast::<u32>().write(player.add(0x9ec).cast::<u32>().read());
        source_bytes.add(0x10).cast::<u32>().write(player.add(0x9f0).cast::<u32>().read());
        source_bytes.add(0x14).write(player.add(0x9f4).read());
        for index in 0..5 {
            string_id_record_assign(
                source_bytes.add(0x18 + index * 0x10).cast(),
                player.add(PLAYER_RECORDS_OFFSET + index * 0x10).cast(),
            );
        }
        source_bytes.add(0x68).cast::<u32>().write(
            player.add(PLAYER_TRAILING_WORD_OFFSET).cast::<u32>().read(),
        );

        let object = handle_deref_or_null(callback_handle);
        let vtable = object.cast::<u32>().read() as *const u32;
        let populate: PopulateSnapshot = core::mem::transmute(
            vtable.add(POPULATE_SNAPSHOT_VTABLE_WORD).read() as usize,
        );
        let callback_object = populate(object, destination);
        let callback: SnapshotCallback = core::mem::transmute(
            callback_object.cast::<u32>().read() as usize,
        );
        let result = callback(callback_object, source, destination, 1);
        scoped_string_id_record_set_destroy(destination);
        scoped_string_id_record_set_destroy(source);
        result
    }

    #[cfg(not(target_os = "none"))]
    {
        host_dispatch(callback_handle)
    }
}

#[cfg(not(target_os = "none"))]
type HostDispatch = unsafe fn(*const *const *mut u8) -> u32;
#[cfg(not(target_os = "none"))]
unsafe fn missing_host_dispatch(_: *const *const *mut u8) -> u32 {
    panic!("install scoped string-id record-set dispatch host operation")
}
#[cfg(not(target_os = "none"))]
static mut HOST_DISPATCH: HostDispatch = missing_host_dispatch;
#[cfg(not(target_os = "none"))]
unsafe fn host_dispatch(callback_handle: *const *const *mut u8) -> u32 {
    HOST_DISPATCH(callback_handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED_HANDLE: *const *const *mut u8 = core::ptr::null();
    static mut RESULT: u32 = 0;

    unsafe fn record_dispatch(handle: *const *const *mut u8) -> u32 {
        OBSERVED_HANDLE = handle;
        RESULT
    }

    #[test]
    fn forwards_the_handle_and_returns_the_callback_result() {
        let _lock = LOCK.lock();
        let old = unsafe { HOST_DISPATCH };
        unsafe {
            HOST_DISPATCH = record_dispatch;
            RESULT = 0xfeed_beef;
            let target = 0x1234usize as *mut u8;
            let cell = &target as *const *mut u8;
            let handle = &cell as *const *const *mut u8;
            assert_eq!(scoped_string_id_record_set_dispatch(handle), RESULT);
            assert_eq!(OBSERVED_HANDLE, handle);
            HOST_DISPATCH = old;
        }
    }

    #[test]
    fn forwards_null_handle_without_prevalidation() {
        let _lock = LOCK.lock();
        let old = unsafe { HOST_DISPATCH };
        unsafe {
            HOST_DISPATCH = record_dispatch;
            RESULT = 0;
            assert_eq!(scoped_string_id_record_set_dispatch(core::ptr::null()), 0);
            assert!(OBSERVED_HANDLE.is_null());
            HOST_DISPATCH = old;
        }
    }
}

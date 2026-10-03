//! Media-player context record constructor at 0x08231854.
//!
//! True extent: 76 bytes (72 instruction bytes through 0x08231898,
//! vtable literal at 0x0823189c; next function at 0x082318a0).
//! Verified outgoing calls: three plain BLs, zero predicated BLs.
//! Plants vtable 0x089a1394, constructs a NULL-owner, zero-mode scoped
//! context at +8 and an empty StringObject at +0x20, captures the media
//! player at +4, clears four words at +0x28..+0x34, and returns this.
//! The caller allocates 0x3c bytes; +0x38 and context padding are untouched.
//! Deliberate deviations: repr(C) expands pointer-bearing members on hosts;
//! existing Rust constructors/getter retain their documented seams and
//! singleton hook-readiness limitations. The unrecovered outer vtable stays
//! a firmware address rather than an invented Rust virtual interface.

use core::ptr;
use crate::scoped_context::{ScopedContext, scoped_context_construct};
use crate::singletons::media_player_get;
use crate::string_object::{StringObject, string_default_construct};

#[repr(C)]
pub struct MediaPlayerContext {
    pub vtable_address: u32,
    pub media_player: *mut u8,
    pub context: ScopedContext,
    pub string: StringObject,
    pub cleared_words: [u32; 4],
    pub opaque_tail: u32,
}

/// Original FUN_08231854: 76-byte extent, three plain BLs, no predicated BLs.
/// Initializes the context/string record without touching its opaque tail.
/// Requires writable, aligned storage for a MediaPlayerContext.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_context_construct(
    this: *mut MediaPlayerContext,
) -> *mut MediaPlayerContext {
    ptr::addr_of_mut!((*this).vtable_address).write(0x089a_1394);
    scoped_context_construct(ptr::addr_of_mut!((*this).context), ptr::null_mut(), 0);
    string_default_construct(ptr::addr_of_mut!((*this).string));
    ptr::addr_of_mut!((*this).media_player).write(media_player_get());
    ptr::addr_of_mut!((*this).cleared_words).write([0; 4]);
    this
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::size_of::<MediaPlayerContext>() == 0x3c);
    assert!(core::mem::offset_of!(MediaPlayerContext, context) == 8);
    assert!(core::mem::offset_of!(MediaPlayerContext, string) == 0x20);
    assert!(core::mem::offset_of!(MediaPlayerContext, cleared_words) == 0x28);
    assert!(core::mem::offset_of!(MediaPlayerContext, opaque_tail) == 0x38);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoped_context::SCOPED_CONTEXT_VTABLE;
    use crate::singletons::{MEDIA_PLAYER_INSTANCE, SINGLETON_LOCK};
    use crate::string_object::STRING_OBJECT_VTABLE;
    use core::mem::{MaybeUninit, size_of, offset_of};

    struct RestoreCache(*mut u8);
    impl Drop for RestoreCache {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(MEDIA_PLAYER_INSTANCE).write(self.0); }
        }
    }

    #[test]
    fn poisoned_storage_initializes_members_preserves_tail_and_padding() {
        let _root = crate::testing::APP_ROOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _singleton = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = RestoreCache(ptr::addr_of!(MEDIA_PLAYER_INSTANCE).read());
            let mut player = [0u8; 0xa6c];
            ptr::addr_of_mut!(MEDIA_PLAYER_INSTANCE).write(player.as_mut_ptr());
            for poison in [0u8, 0xa5, 0xff] {
                let mut storage = MaybeUninit::<MediaPlayerContext>::uninit();
                let record = storage.as_mut_ptr();
                ptr::write_bytes(record.cast::<u8>(), poison, size_of::<MediaPlayerContext>());
                assert_eq!(media_player_context_construct(record), record);
                let record_ref = &*record;
                assert_eq!(record_ref.vtable_address, 0x089a_1394);
                assert_eq!(record_ref.media_player, player.as_mut_ptr());
                assert_eq!(record_ref.context.vtable, &SCOPED_CONTEXT_VTABLE as *const _);
                assert_eq!(record_ref.context.owner_valid, 0);
                assert!(record_ref.context.owner.is_null());
                assert!(record_ref.context.service_context.is_null());
                assert!(record_ref.context.registry_token.is_null());
                assert_eq!(record_ref.context.mode, 0);
                assert_eq!(record_ref.string.vtable, &STRING_OBJECT_VTABLE as *const _);
                assert!(record_ref.string.payload.is_null());
                assert_eq!(record_ref.cleared_words, [0; 4]);
                assert_eq!(record_ref.opaque_tail, u32::from_ne_bytes([poison; 4]));
                let padding_start = offset_of!(MediaPlayerContext, context)
                    + offset_of!(ScopedContext, mode) + 1;
                let padding_end = offset_of!(MediaPlayerContext, context) + size_of::<ScopedContext>();
                for offset in padding_start..padding_end {
                    assert_eq!(record.cast::<u8>().add(offset).read(), poison);
                }
            }
        }
    }
}

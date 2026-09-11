//! Constructor for a vtable-bearing record with a retained shared handle.
//!
//! ## Original: `FUN_083e78b4` @ 0x083e78b4 (68 bytes)
//!
//! The raw extent is 60 instruction bytes plus the two literal-pool words at
//! 0x083e78f0 and 0x083e78f4; the next function starts at 0x083e78f8.
//! Decoding every ARM B/BL immediate in `osos.dec` finds eight inbound direct
//! calls, all unconditional `bl` (0x082a782c, 0x082a7dc4, 0x082a8f80,
//! 0x083d8044, 0x083d8074, 0x083d80d4, 0x083dae68, and 0x083dae9c), with no
//! predicated forms or direct tail branches.
//!
//! The constructor first plants descriptor 0x089a8aac, invokes the shared
//! handle initializer on its `+0x18` word, clears the six words at
//! `+0x1c..+0x30`, then replaces the descriptor with 0x089a8b04 and returns
//! the incoming storage. It deliberately preserves words `+0x04..+0x14` and
//! the shared-handle initializer's `+0x18` result.
//!
//! `FUN_082a8b68` is not yet ported (and has no ledger entry). Target builds
//! call its verified fixed address; host builds use the replaceable seam below.
//! The default host seam is a no-op because the initializer's global shared
//! object is target runtime state, not a recoverable host object. This is the
//! only deliberate host deviation.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

/// The descriptor written before calling `FUN_082a8b68`.
pub const SHARED_HANDLE_BASE_DESCRIPTOR: u32 = 0x089a_8aac;
/// The descriptor installed after the shared handle is initialized.
pub const SHARED_HANDLE_DESCRIPTOR: u32 = 0x089a_8b04;
#[cfg(target_os = "none")]
const RETAIL_SHARED_HANDLE_INITIALIZE: usize = 0x082a_8b68;

/// Target-layout record constructed by [`vtable_shared_handle_construct`].
#[repr(C)]
pub struct VtableSharedHandle {
    /// +0x00: base descriptor before the shared-handle initializer, derived
    /// descriptor on return.
    pub descriptor: u32,
    /// +0x04..+0x14: not written by this constructor.
    pub preserved: [u32; 5],
    /// +0x18: global shared-object handle written by `FUN_082a8b68`.
    pub shared_handle: u32,
    /// +0x1c..+0x30: cleared after the shared-handle initializer.
    pub cleared: [u32; 6],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 52] = [0; core::mem::size_of::<VtableSharedHandle>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 24] = [0; core::mem::offset_of!(VtableSharedHandle, shared_handle)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 28] = [0; core::mem::offset_of!(VtableSharedHandle, cleared)];

/// ABI of the unported shared-handle initializer.
pub type SharedHandleInitialize = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shared_handle_initialize(slot: *mut u32) {
    let initialize: SharedHandleInitialize = core::mem::transmute(RETAIL_SHARED_HANDLE_INITIALIZE);
    initialize(slot);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unported_shared_handle_initialize(_slot: *mut u32) -> *mut u32 {
    core::ptr::null_mut()
}

/// Host-side replacement for unported `FUN_082a8b68`.
#[cfg(not(target_os = "none"))]
pub static mut SHARED_HANDLE_INITIALIZE: SharedHandleInitialize = unported_shared_handle_initialize;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shared_handle_initialize(slot: *mut u32) {
    let initialize = core::ptr::read_volatile(addr_of!(SHARED_HANDLE_INITIALIZE));
    initialize(slot);
}

/// `vtable_shared_handle_construct` — original `FUN_083e78b4` @
/// `0x083e78b4` (60 code bytes + 8 literal-pool bytes).
///
/// Installs the base descriptor, initializes the `+0x18` shared handle, clears
/// the trailing six words, installs the derived descriptor, and returns
/// `storage`. `storage` must be valid for one aligned [`VtableSharedHandle`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_shared_handle_construct(
    storage: *mut VtableSharedHandle,
) -> *mut VtableSharedHandle {
    (*storage).descriptor = SHARED_HANDLE_BASE_DESCRIPTOR;
    shared_handle_initialize(core::ptr::addr_of_mut!((*storage).shared_handle));
    (*storage).cleared = [0; 6];
    (*storage).descriptor = SHARED_HANDLE_DESCRIPTOR;
    storage
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut OBSERVED_SLOT: *mut u32 = core::ptr::null_mut();
    static mut OBSERVED_BASE_DESCRIPTOR: u32 = 0;
    static mut INITIALIZER_CALLS: u32 = 0;

    unsafe extern "C" fn recording_initializer(slot: *mut u32) -> *mut u32 {
        OBSERVED_SLOT = slot;
        OBSERVED_BASE_DESCRIPTOR = slot.sub(6).read();
        INITIALIZER_CALLS += 1;
        slot.write(0xfeed_beef);
        core::ptr::null_mut()
    }

    unsafe fn reset() {
        OBSERVED_SLOT = core::ptr::null_mut();
        OBSERVED_BASE_DESCRIPTOR = 0;
        INITIALIZER_CALLS = 0;
        SHARED_HANDLE_INITIALIZE = recording_initializer;
    }

    #[test]
    fn initializes_only_the_observed_words_and_returns_storage() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset();
            let mut record = VtableSharedHandle {
                descriptor: 0x1111_2222,
                preserved: [0x3333_4444, 0x5555_6666, 0x7777_8888, 0x9999_aaaa, 0xbbbb_cccc],
                shared_handle: 0xdddd_eeee,
                cleared: [0x0123_4567; 6],
            };

            let returned = vtable_shared_handle_construct(addr_of_mut!(record));

            assert_eq!(returned, addr_of_mut!(record));
            assert_eq!(INITIALIZER_CALLS, 1);
            assert_eq!(OBSERVED_SLOT, addr_of_mut!(record.shared_handle));
            assert_eq!(OBSERVED_BASE_DESCRIPTOR, SHARED_HANDLE_BASE_DESCRIPTOR);
            assert_eq!(record.descriptor, SHARED_HANDLE_DESCRIPTOR);
            assert_eq!(record.preserved, [0x3333_4444, 0x5555_6666, 0x7777_8888, 0x9999_aaaa, 0xbbbb_cccc]);
            assert_eq!(record.shared_handle, 0xfeed_beef);
            assert_eq!(record.cleared, [0; 6]);
        }
    }

    #[test]
    fn ignores_the_initializer_return_value() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset();
            let mut record = VtableSharedHandle {
                descriptor: 0,
                preserved: [0; 5],
                shared_handle: 0,
                cleared: [u32::MAX; 6],
            };

            assert_eq!(vtable_shared_handle_construct(addr_of_mut!(record)), addr_of_mut!(record));
            assert_eq!(INITIALIZER_CALLS, 1);
            assert_eq!(addr_of!(record.shared_handle).cast_mut(), OBSERVED_SLOT);
            assert_eq!(record.descriptor, SHARED_HANDLE_DESCRIPTOR);
            assert_eq!(record.shared_handle, 0xfeed_beef);
            assert_eq!(record.cleared, [0; 6]);
        }
    }
}

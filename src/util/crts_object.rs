//! crts_object_destroy — original: `FUN_0809e160` @ 0x0809e160 (92 bytes;
//! 24 direct `bl` call sites, binary-scanned).
//!
//! In-place destructor body for the 0x58-byte `"crts"`-tagged object
//! family. The raw ARM:
//!
//! ```text
//! if tag_guard(this) == 0 { return -50; }   // mvn r0, #0x31
//! if this->handle_08 != 0 { memh_destroy(this->handle_08); }
//! if this->handle_0c != 0 { memh_destroy(this->handle_0c); }
//! if this->handle_10 != 0 { memh_destroy(this->handle_10); }
//! table_teardown(this, 1);                   // status discarded
//! bzero(this, 0x58);
//! return 0;
//! ```
//!
//! The tag guard is the separately linked 0x080a7714: it returns one only
//! for a non-NULL object whose first word is `0x7374_7263` (in-memory
//! bytes `"crts"`; its semantic identity is not established) and zero for
//! NULL or any other tag. The three handles belong to the `"MemH"`
//! managed-buffer family destroyed by 0x0805d028 (itself NULL-safe, but
//! every call here is guarded by `blne`). 0x080d86b0 is the object's
//! table teardown: with `force != 0` it frees the entry arrays at +0x14
//! and +0x18 (a 0x10000-entry u16-indexed table) and rewrites the +0x04
//! flags word; it is separately unported and not assigned an identity
//! beyond that verified behaviour.
//!
//! # Extent and call census
//!
//! The next separately entered function begins at 0x0809e1bc, so the
//! extent is exactly 92 bytes; Ghidra's size is correct for once.
//! Decoding every ARM B/BL word in osos.dec finds exactly 24 direct call
//! sites, all unconditional `bl` (three in the array-destructor loops of
//! the 0x080490xx family, 21 in the table-clear at 0x080da928); there are
//! no predicated forms, no tail branches, and the address occurs in no
//! data word, so the destructor is never dispatched virtually. Caller
//! context: 0x080490b8 destroys embedded sub-objects at +0x34, +0x8c and
//! an array of stride 0x58 at +0xe4; 0x083b467c sets a vtable, then calls
//! this destructor on a heap object and follows with tag-2
//! `operator_delete` — the classic split-destructor shape.
//!
//! # Deliberate deviations
//!
//! - The verified four-instruction tag guard of 0x080a7714 is inlined
//!   rather than given a dispatch seam (the util/tagged_counter.rs
//!   precedent); no identity is invented for it.
//! - The two unported non-trivial callees dispatch through the volatile
//!   seams [`MEMH_HANDLE_DESTROY`] and [`CRTS_TABLE_TEARDOWN`]; their
//!   target defaults transmute the retail addresses 0x0805d028 and
//!   0x080d86b0, so the port is hook-ready on device, while host tests
//!   install recording mocks.
//! - 0x0805cfb4 is already ported as [`crate::libc::bzero::bzero`]; it is
//!   reached through the volatile [`CRTS_OBJECT_ZERO`] slot (wired default:
//!   the port) so LLVM cannot inline the 76-byte fill and erase the stock
//!   `bl` boundary.
//! - Handle fields are modelled as `u32` words, never native pointers:
//!   this function only compares and forwards them, and the model keeps
//!   4-byte field spacing on both the 32-bit target and 64-bit hosts.

use core::ptr;

/// First word required by the inlined 0x080a7714 guard (`"crts"` bytes).
pub const CRTS_TAG: u32 = 0x7374_7263;

/// Failure status (`mvn r0, #0x31` in the original): invalid tag or NULL.
pub const ERR_INVALID_OBJECT: i32 = -50;

/// Total object extent zeroed by the destructor, in bytes.
pub const CRTS_OBJECT_SIZE: usize = 0x58;

/// RetailOS load address of the unported `"MemH"` handle destructor.
pub const MEMH_HANDLE_DESTROY_ADDRESS: usize = 0x0805_d028;

/// RetailOS load address of the unported table teardown.
pub const CRTS_TABLE_TEARDOWN_ADDRESS: usize = 0x080d_86b0;

/// ABI of the `"MemH"` managed-buffer destructor at 0x0805d028.
pub type MemhHandleDestroy = unsafe extern "C" fn(handle: u32);

/// ABI of the object table teardown at 0x080d86b0. Its status is
/// discarded by the destructor, exactly as in the original.
pub type CrtsTableTeardown = unsafe extern "C" fn(this: *mut CrtsObject, force: u32) -> i32;

/// The verified header of the `"crts"`-tagged object family.
///
/// All fields are 32-bit words so the layout is identical on the 32-bit
/// target and on 64-bit hosts. `flags` and the `opaque_14` tail are owned
/// by the teardown callee and the bzero fill; this destructor itself only
/// reads `tag` and the three handle words.
#[repr(C)]
pub struct CrtsObject {
    /// +0x00 — must equal [`CRTS_TAG`].
    pub tag: u32,
    /// +0x04 — flags word tested and rewritten by the teardown callee.
    pub flags: u32,
    /// +0x08 — first `"MemH"` managed-buffer handle, zero when absent.
    pub handle_08: u32,
    /// +0x0c — second `"MemH"` managed-buffer handle, zero when absent.
    pub handle_0c: u32,
    /// +0x10 — third `"MemH"` managed-buffer handle, zero when absent.
    pub handle_10: u32,
    /// +0x14..+0x58 — opaque tail; +0x14/+0x18 hold the teardown's table
    /// arrays, the rest is unknown. Zeroed whole by the destructor.
    pub opaque_14: [u32; 17],
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_memh_handle_destroy(handle: u32) {
    let body: MemhHandleDestroy = core::mem::transmute(MEMH_HANDLE_DESTROY_ADDRESS);
    body(handle);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_memh_handle_destroy(_handle: u32) {
    panic!("crts_object_destroy requires MemH destructor 0x0805d028")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_crts_table_teardown(this: *mut CrtsObject, force: u32) -> i32 {
    let body: CrtsTableTeardown = core::mem::transmute(CRTS_TABLE_TEARDOWN_ADDRESS);
    body(this, force)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_crts_table_teardown(_this: *mut CrtsObject, _force: u32) -> i32 {
    panic!("crts_object_destroy requires table teardown 0x080d86b0")
}

/// Active boundary for the unported `"MemH"` handle destructor. On the
/// target it calls directly into retailOS; host tests replace it with a
/// recording implementation.
#[cfg(target_os = "none")]
pub static mut MEMH_HANDLE_DESTROY: MemhHandleDestroy = retail_memh_handle_destroy;

/// Active host boundary for the unported `"MemH"` handle destructor.
#[cfg(not(target_os = "none"))]
pub static mut MEMH_HANDLE_DESTROY: MemhHandleDestroy = missing_memh_handle_destroy;

/// Active boundary for the unported table teardown, same policy as
/// [`MEMH_HANDLE_DESTROY`].
#[cfg(target_os = "none")]
pub static mut CRTS_TABLE_TEARDOWN: CrtsTableTeardown = retail_crts_table_teardown;

/// Active host boundary for the unported table teardown.
#[cfg(not(target_os = "none"))]
pub static mut CRTS_TABLE_TEARDOWN: CrtsTableTeardown = missing_crts_table_teardown;

#[inline(always)]
unsafe fn memh_handle_destroy() -> MemhHandleDestroy {
    ptr::read_volatile(ptr::addr_of!(MEMH_HANDLE_DESTROY))
}

#[inline(always)]
unsafe fn crts_table_teardown() -> CrtsTableTeardown {
    ptr::read_volatile(ptr::addr_of!(CRTS_TABLE_TEARDOWN))
}

/// Zero-fill boundary for the destructor's final `bl 0x0805cfb4`. The wired
/// default is the ported [`crate::libc::bzero::bzero`]; the volatile slot
/// keeps LLVM from inlining the fill and erasing the stock call boundary.
pub static mut CRTS_OBJECT_ZERO: unsafe extern "C" fn(*mut u8, i32) =
    crate::libc::bzero::bzero;

#[inline(always)]
unsafe fn crts_object_zero() -> unsafe extern "C" fn(*mut u8, i32) {
    ptr::read_volatile(ptr::addr_of!(CRTS_OBJECT_ZERO))
}

/// crts_object_destroy — original: `FUN_0809e160` @ 0x0809e160
/// (92 bytes).
///
/// Releases every resource of a valid `"crts"`-tagged object: destroys
/// its three `"MemH"` handles in offset order, tears down its table with
/// `force = 1`, and zeroes the whole 0x58-byte object, returning 0.
/// Returns [`ERR_INVALID_OBJECT`] for NULL or an unrecognised tag,
/// leaving the object untouched.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crts_object_destroy(this: *mut CrtsObject) -> i32 {
    if this.is_null() || (*this).tag != CRTS_TAG {
        return ERR_INVALID_OBJECT;
    }
    let handle = (*this).handle_08;
    if handle != 0 {
        memh_handle_destroy()(handle);
    }
    let handle = (*this).handle_0c;
    if handle != 0 {
        memh_handle_destroy()(handle);
    }
    let handle = (*this).handle_10;
    if handle != 0 {
        memh_handle_destroy()(handle);
    }
    let _ = crts_table_teardown()(this, 1);
    crts_object_zero()(this as *mut u8, CRTS_OBJECT_SIZE as i32);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    static DESTROY_LOCK: Mutex<()> = Mutex::new(());

    /// Handles observed by the recording MemH destructor, in call order.
    static mut DESTROYED: Vec<u32> = Vec::new();
    /// (this, force) pairs observed by the recording teardown.
    static mut TEARDOWN_CALLS: Vec<(usize, u32)> = Vec::new();
    /// Status the recording teardown returns.
    static mut TEARDOWN_STATUS: i32 = 0;

    unsafe extern "C" fn recording_memh_handle_destroy(handle: u32) {
        DESTROYED.push(handle);
    }

    unsafe extern "C" fn recording_crts_table_teardown(this: *mut CrtsObject, force: u32) -> i32 {
        TEARDOWN_CALLS.push((this as usize, force));
        TEARDOWN_STATUS
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                MEMH_HANDLE_DESTROY = missing_memh_handle_destroy;
                CRTS_TABLE_TEARDOWN = missing_crts_table_teardown;
                DESTROYED = Vec::new();
                TEARDOWN_CALLS = Vec::new();
                TEARDOWN_STATUS = 0;
            }
        }
    }

    /// Installs the recording seams and returns the lock and reset guard.
    fn mock() -> (std::sync::MutexGuard<'static, ()>, Reset) {
        let guard = DESTROY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            MEMH_HANDLE_DESTROY = recording_memh_handle_destroy;
            CRTS_TABLE_TEARDOWN = recording_crts_table_teardown;
        }
        (guard, Reset)
    }

    /// A fixture with the tag and all words set to a canary pattern.
    fn canary_object() -> CrtsObject {
        CrtsObject {
            tag: CRTS_TAG,
            flags: 0xaaaa_aaaa,
            handle_08: 0,
            handle_0c: 0,
            handle_10: 0,
            opaque_14: [0xaaaa_aaaa; 17],
        }
    }

    #[test]
    fn layout_is_exactly_0x58_bytes() {
        assert_eq!(core::mem::size_of::<CrtsObject>(), CRTS_OBJECT_SIZE);
        assert_eq!(core::mem::align_of::<CrtsObject>(), 4);
    }

    #[test]
    fn null_object_returns_err_invalid_and_calls_nothing() {
        let _lock = DESTROY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _reset = Reset;
        unsafe {
            assert_eq!(crts_object_destroy(ptr::null_mut()), ERR_INVALID_OBJECT);
        }
    }

    #[test]
    fn bad_tag_returns_err_invalid_and_leaves_object_untouched() {
        let _lock = DESTROY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _reset = Reset;
        let mut object = canary_object();
        object.tag = 0x7374_7264; // "drts"
        object.handle_08 = 0x1111_1111;
        let before: Vec<u8> = unsafe {
            std::slice::from_raw_parts(&object as *const CrtsObject as *const u8, CRTS_OBJECT_SIZE)
                .to_vec()
        };
        unsafe {
            assert_eq!(crts_object_destroy(&mut object), ERR_INVALID_OBJECT);
        }
        let after: Vec<u8> = unsafe {
            std::slice::from_raw_parts(&object as *const CrtsObject as *const u8, CRTS_OBJECT_SIZE)
                .to_vec()
        };
        assert_eq!(before, after, "a rejected object is not touched at all");
    }

    #[test]
    fn valid_object_destroys_handles_in_offset_order_then_teardowns_then_zeroes() {
        let (_lock, _reset) = mock();
        let mut object = canary_object();
        object.handle_08 = 0x0810_0008;
        object.handle_0c = 0x0810_000c;
        object.handle_10 = 0x0810_0010;
        let this = &mut object as *mut CrtsObject;
        unsafe {
            assert_eq!(crts_object_destroy(this), 0);
            assert_eq!(
                DESTROYED,
                [0x0810_0008, 0x0810_000c, 0x0810_0010],
                "handles are destroyed in +0x08, +0x0c, +0x10 order"
            );
            assert_eq!(TEARDOWN_CALLS, [(this as usize, 1)], "teardown runs once, forced");
        }
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(this as *const u8, CRTS_OBJECT_SIZE) };
        assert!(bytes.iter().all(|&b| b == 0), "the whole object is zeroed");
    }

    #[test]
    fn absent_handles_skip_the_destroy_but_teardown_still_runs() {
        let (_lock, _reset) = mock();
        let mut object = canary_object();
        object.handle_0c = 0x0bad_f00d;
        let this = &mut object as *mut CrtsObject;
        unsafe {
            assert_eq!(crts_object_destroy(this), 0);
            assert_eq!(DESTROYED, [0x0bad_f00d], "only the present handle is destroyed");
            assert_eq!(TEARDOWN_CALLS.len(), 1);
        }
    }

    #[test]
    fn teardown_status_is_discarded() {
        let (_lock, _reset) = mock();
        let mut object = canary_object();
        unsafe {
            TEARDOWN_STATUS = ERR_INVALID_OBJECT;
            assert_eq!(
                crts_object_destroy(&mut object),
                0,
                "the destructor returns its own success, not the teardown's"
            );
        }
    }
}

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
//! flags word; it is ported as `crts_table_teardown`.
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
//! - The verified tag guard at 0x080a7714 is ported as
//!   [`crate::util::crts_tag::crts_has_tag`] and called directly; it needs no
//!   replaceable dispatch seam.
//! - Table teardown and the `"MemH"` destructor are direct calls to their
//!   verified Rust ports; neither needs a replaceable dispatch seam.
//! - 0x0805cfb4 is already ported as [`crate::libc::bzero::bzero`]; it is
//!   reached through the volatile [`CRTS_OBJECT_ZERO`] slot (wired default:
//!   the port) so LLVM cannot inline the 76-byte fill and erase the stock
//!   `bl` boundary.
//! - Handle fields are modelled as `u32` words, never native pointers:
//!   this function only compares and forwards them, and the model keeps
//!   4-byte field spacing on both the 32-bit target and 64-bit hosts.

use core::ptr;
use crate::util::crts_tag::crts_has_tag;
#[cfg(test)]
use crate::util::crts_tag::CRTS_TAG;



/// Failure status (`mvn r0, #0x31` in the original): invalid tag or NULL.
pub const ERR_INVALID_OBJECT: i32 = -50;

/// Total object extent zeroed by the destructor, in bytes.
pub const CRTS_OBJECT_SIZE: usize = 0x58;


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
    if crts_has_tag(this.cast()) == 0 {
        return ERR_INVALID_OBJECT;
    }
    let handle = (*this).handle_08;
    if handle != 0 {
        crate::heap::memh_handle::memh_handle_destroy(
            handle as usize as *mut crate::heap::memh_handle::MemhHandle,
        );
    }
    let handle = (*this).handle_0c;
    if handle != 0 {
        crate::heap::memh_handle::memh_handle_destroy(
            handle as usize as *mut crate::heap::memh_handle::MemhHandle,
        );
    }
    let handle = (*this).handle_10;
    if handle != 0 {
        crate::heap::memh_handle::memh_handle_destroy(
            handle as usize as *mut crate::heap::memh_handle::MemhHandle,
        );
    }
    let _ = crate::util::crts_table_teardown::crts_table_teardown(this, 1);
    crts_object_zero()(this as *mut u8, CRTS_OBJECT_SIZE as i32);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    /// Valid tag with absent resources and a canary flags word.
    fn canary_object() -> CrtsObject {
        CrtsObject {
            tag: CRTS_TAG,
            flags: 0xaaaa_aaaa,
            handle_08: 0,
            handle_0c: 0,
            handle_10: 0,
            opaque_14: [0; 17],
        }
    }

    #[test]
    fn layout_is_exactly_0x58_bytes() {
        assert_eq!(core::mem::size_of::<CrtsObject>(), CRTS_OBJECT_SIZE);
        assert_eq!(core::mem::align_of::<CrtsObject>(), 4);
    }

    #[test]
    fn null_object_returns_err_invalid_and_calls_nothing() {
        unsafe {
            assert_eq!(crts_object_destroy(ptr::null_mut()), ERR_INVALID_OBJECT);
        }
    }

    #[test]
    fn bad_tag_returns_err_invalid_and_leaves_object_untouched() {
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
    fn valid_object_teardowns_then_zeroes_when_no_memh_handles_are_present() {
        let mut object = canary_object();
        let this = &mut object as *mut CrtsObject;
        unsafe {
            assert_eq!(crts_object_destroy(this), 0);
        }
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(this as *const u8, CRTS_OBJECT_SIZE) };
        assert!(bytes.iter().all(|&b| b == 0), "the whole object is zeroed");
    }

}

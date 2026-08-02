//! `template_binding` — the retailOS controller object's name accessor
//! at 0x081346e4.
//!
//! The function sits inside the 0x08134600..0x08134d00 block that
//! `app/registry` already claims for the framework's observable base, and
//! its immediate predecessor 0x081346c8 (28 bytes, back-to-back with no
//! padding) reaches a different member of the same opaque `this` — this
//! module is where that sibling lands too.
//!
//! What it does, from the raw bytes (`arm-none-eabi-objdump` over
//! `work/firmware/osos.dec` at load base 0x08000000, cross-checked
//! against `decomp/osos.asm`): it reads the embedded two-word
//! `StringObject` at `this + 0x28` through the ported
//! `string_object_c_str` @ 0x082a50b0 and returns that C string — except
//! when it equals a one-byte ROM sentinel, in which case it returns a ROM
//! default instead. It is the base of a 114-member override family: every
//! one of the 114 `bl` sites is followed by the identical 44-byte wrapper
//! `bl 0x081346e4 / adr r1,"CntrlHistoryFn" / bl strcmp / cmp r0,#0 /
//!  movne r0,this / popne / bne 0x081346e4 / ldreq r0,[pool] / pop`,
//! i.e. each derived class substitutes its own ROM string when the
//! inherited name is the framework's `"CntrlHistoryFn"` marker. That
//! marker occurs 158 times in the image, and the app-layer literal pools
//! carry it in per-translation-unit triples together with
//! `"TSilverCntlr"` and the unit's own controller names
//! (`"TCNotesDispatcher"`, `"TCClock"`, `"TCVoiceMemos"`,
//! `"TDiskModeCntlr"`, ... @ 0x083f5cbc onward), so the family belongs to
//! the `TSilverCntlr` controller framework. The accessor itself makes no
//! vtable call and is not itself an override.
//!
//! Verified numbers (every B/BL word in the 10 597 864-byte `osos.dec`
//! decoded and its target computed): 114 `bl` sites plus 114 tail `b`
//! sites, the second half of each wrapper's `bne 0x081346e4`. 48 bytes of
//! code plus the two-word literal pool it owns at
//! 0x08134714..0x0813471b (56 bytes total); the next function, a lone
//! `bx lr`, starts at 0x0813471c.
//!
//! Deviations:
//!
//! - The two ROM string constants the function loads are *content*, not
//!   addresses a host can reproduce: this toolchain resolves short string
//!   literals to any matching byte run anywhere in the image (the same
//!   phenomenon `cxx/string_object`'s `STRING_OBJECT_EMPTY_CSTR_ADDRESS`
//!   documents), so the sentinel lands on the first byte of
//!   `b 0x083e26cc` and the default on the first byte of
//!   `ldr r1,[r4,#0]`. The port models the bytes
//!   ([`NAME_SENTINEL_CSTR`] = `0x12 0x00`, [`NAME_DEFAULT_CSTR`] = the
//!   empty string) and keeps the ROM addresses as named constants.
//! - `string_object_c_str` @ 0x082a50b0 and `strcmp` @ 0x08391e38 are
//!   already ported, so they are called directly — no dispatch seam. The
//!   original calls `string_object_c_str` twice (once per branch); the
//!   port keeps both calls so the structure survives.
//! - The class identity behind `this` is inferred, not proven: the port
//!   therefore treats the object as opaque bytes and claims only the
//!   offset the instruction spells out (`add r0, r0, #0x28`).

use crate::cxx::string_object::{string_object_c_str, StringObject};
use crate::libc::strcmp::strcmp;

/// Byte offset of the embedded name string object — the original's
/// `add r0, r0, #0x28` @ 0x081346ec.
pub const NAME_OFFSET: usize = 0x28;

/// ROM address of the sentinel the name is compared against
/// (literal-pool word @ 0x08134714 holds 0x083e267c — binary-verified
/// against `osos.dec`). The byte run there is `0x12 0x00`; see the module
/// header for why a code address holds a string constant.
pub const NAME_SENTINEL_CSTR_ADDRESS: usize = 0x083e267c;

/// ROM address of the substituted default (literal-pool word @
/// 0x08134718 holds 0x083e266c — binary-verified). The byte there is
/// 0x00, i.e. the empty C string.
pub const NAME_DEFAULT_CSTR_ADDRESS: usize = 0x083e266c;

/// Modeled sentinel: the exact bytes at [`NAME_SENTINEL_CSTR_ADDRESS`].
pub static NAME_SENTINEL_CSTR: [u8; 2] = [0x12, 0x00];

/// Modeled default: the empty C string at [`NAME_DEFAULT_CSTR_ADDRESS`].
pub static NAME_DEFAULT_CSTR: u8 = 0;

/// template_binding_name_or_default — original: `FUN_081346e4` @
/// 0x081346e4 (48 bytes of code plus a two-word literal pool; 114 `bl`
/// and 114 tail `b` call sites, binary-scanned over `osos.dec`).
///
/// Returns the C string of the object's embedded name at
/// `this + 0x28`, substituting [`NAME_DEFAULT_CSTR`] when that string
/// equals [`NAME_SENTINEL_CSTR`]. No NULL guard on `this` — the original
/// faults on a NULL `this`, and so does the port; a NULL *payload* is
/// handled inside `string_object_c_str`, which yields its shared empty
/// string (never equal to the sentinel, so it is returned unchanged).
///
/// # Safety
///
/// `this` must point into a readable allocation containing a valid
/// [`StringObject`] at byte offset [`NAME_OFFSET`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn template_binding_name_or_default(this: *mut u8) -> *const u8 {
    let name = this.add(NAME_OFFSET) as *const StringObject;
    if strcmp(string_object_c_str(name), NAME_SENTINEL_CSTR.as_ptr()) != 0 {
        return string_object_c_str(name);
    }
    &NAME_DEFAULT_CSTR
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    /// Object big enough to hold the name string object at +0x28; the
    /// layout beyond that offset is irrelevant to this port.
    const OBJECT_SIZE: usize = 0x100;

    fn object_with_name(payload: *mut u8) -> Vec<u8> {
        let mut object = std::vec![0u8; OBJECT_SIZE];
        unsafe {
            let name = object.as_mut_ptr().add(NAME_OFFSET) as *mut StringObject;
            (*name).vtable = core::ptr::null();
            (*name).payload = payload;
        }
        object
    }

    #[test]
    fn sentinel_model_matches_the_rom_bytes_and_addresses() {
        assert_eq!(NAME_SENTINEL_CSTR, [0x12, 0x00]);
        assert_eq!(NAME_DEFAULT_CSTR, 0);
        assert_eq!(NAME_SENTINEL_CSTR_ADDRESS, 0x083e267c);
        assert_eq!(NAME_DEFAULT_CSTR_ADDRESS, 0x083e266c);
    }

    #[test]
    fn an_ordinary_name_is_returned_as_the_payload_pointer_itself() {
        let mut name = *b"TCNotesDispatcher\0";
        let mut object = object_with_name(name.as_mut_ptr());

        let result = unsafe { template_binding_name_or_default(object.as_mut_ptr()) };

        assert_eq!(result, name.as_ptr());
    }

    #[test]
    fn a_name_equal_to_the_sentinel_is_replaced_by_the_default() {
        let mut name = [0x12u8, 0x00];
        let mut object = object_with_name(name.as_mut_ptr());

        let result = unsafe { template_binding_name_or_default(object.as_mut_ptr()) };

        assert_eq!(result, &NAME_DEFAULT_CSTR as *const u8);
        assert_eq!(unsafe { result.read() }, 0);
    }

    #[test]
    fn a_name_that_only_starts_with_the_sentinel_byte_is_kept() {
        // strcmp, not memcmp: the extra byte makes the strings differ.
        let mut name = [0x12u8, b'x', 0x00];
        let mut object = object_with_name(name.as_mut_ptr());

        let result = unsafe { template_binding_name_or_default(object.as_mut_ptr()) };

        assert_eq!(result, name.as_ptr());
    }

    #[test]
    fn the_empty_name_is_not_the_sentinel_and_survives() {
        let mut name = [0x00u8];
        let mut object = object_with_name(name.as_mut_ptr());

        let result = unsafe { template_binding_name_or_default(object.as_mut_ptr()) };

        assert_eq!(result, name.as_ptr());
    }

    #[test]
    fn a_null_payload_yields_the_shared_empty_string_not_the_default() {
        let mut object = object_with_name(core::ptr::null_mut());
        let name = unsafe { object.as_mut_ptr().add(NAME_OFFSET) as *const StringObject };

        let result = unsafe { template_binding_name_or_default(object.as_mut_ptr()) };

        assert_eq!(result, unsafe { string_object_c_str(name) });
        assert_ne!(result, &NAME_DEFAULT_CSTR as *const u8);
        assert_eq!(unsafe { result.read() }, 0);
    }

}

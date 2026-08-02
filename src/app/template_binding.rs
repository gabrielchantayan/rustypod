//! `template_binding` — the two back-to-back accessors of the retailOS
//! controller object at 0x081346c8 and 0x081346e4.
//!
//! The two functions are literally adjacent in the image
//! (0x081346c8 + 28 = 0x081346e4, no padding, no literal pool between
//! them) and sit inside the 0x08134600..0x08134d00 block that
//! `app/registry` already claims for the framework's observable base.
//! Both take the same opaque `this` and reach different members of it,
//! so the port keeps them in one module and models the object by byte
//! offset only.
//!
//! What the block does, from the raw bytes (`arm-none-eabi-objdump` over
//! `work/firmware/osos.dec` at load base 0x08000000, cross-checked
//! against `decomp/osos.asm`):
//!
//! - [`template_binding_name_or_default`] @ 0x081346e4 reads the
//!   embedded two-word `StringObject` at `this + 0x28` through the
//!   ported `string_object_c_str` @ 0x082a50b0 and returns that C
//!   string — except when it equals a one-byte ROM sentinel, in which
//!   case it returns a ROM default instead. It is the base of a
//!   114-member override family: every one of the 114 `bl` sites is
//!   followed by the identical 44-byte wrapper
//!   `bl 0x081346e4 / adr r1,"CntrlHistoryFn" / bl strcmp /
//!    cmp r0,#0 / movne r0,this / popne / bne 0x081346e4 /
//!    ldreq r0,[pool] / pop`, i.e. each derived class substitutes its own
//!   ROM string when the inherited name is the framework's
//!   `"CntrlHistoryFn"` marker. That marker string occurs 158 times in
//!   the image, and the app-layer literal pools carry it in
//!   per-translation-unit triples together with `"TSilverCntlr"` and the
//!   unit's own controller names (`"TCNotesDispatcher"`, `"TCClock"`,
//!   `"TCVoiceMemos"`, `"TDiskModeCntlr"`, ... @ 0x083f5cbc onward), so
//!   the family belongs to the `TSilverCntlr` controller framework. The
//!   accessor itself makes no vtable call and is not itself an override.
//!
//! - [`template_binding_map_assign`] @ 0x081346c8 copy-assigns the
//!   container member at `this + 0x94` from a caller-supplied source
//!   (`bl 0x083c2130`, a red-black-tree `operator=` whose header word
//!   lives at `member + 0x10`, i.e. `this + 0xa4`) and then TAIL-BRANCHES
//!   to 0x08134938, which walks that very container — it begins with
//!   `ldr r0,[this+0xa4]` — and returns 1 only when every entry
//!   validates. The walk checks each entry's name against a
//!   NULL-terminated name table (0x08134c70, `strcmp` loop) and
//!   dispatches vtable slot +0x114 per key (0x08134ad4), so the member is
//!   the object's *name-keyed binding map* and the return value is
//!   "every bound name is known".
//!
//! Verified numbers (every B/BL word in the 10 597 864-byte
//! `osos.dec` decoded and its target computed):
//!
//! | function   | code size | `bl` sites | tail `b` sites |
//! |------------|-----------|-----------|----------------|
//! | 0x081346c8 | 28 bytes  | 116       | 0              |
//! | 0x081346e4 | 48 bytes  | 114       | 114            |
//!
//! 0x081346e4 additionally owns the two-word literal pool at
//! 0x08134714..0x0813471b (total extent 56 bytes); the next function
//! (`bx lr`) starts at 0x0813471c. 0x081346c8 has no pool. The 114 tail
//! `b` sites are the second half of each wrapper's `bne 0x081346e4`.
//!
//! Deviations:
//!
//! - The two ROM string constants 0x081346e4 loads are *content*, not
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
//! - 0x081346c8's two callees are NOT ported, so they go through the
//!   [`TEMPLATE_BINDING_OPS`] `read_volatile` seam (house pattern — see
//!   `cxx/string_object`'s `STRING_OBJECT_ASSIGN_CSTR_OPS`).
//! - The class identity behind `this` is inferred, not proven: the port
//!   therefore treats the object as opaque bytes and claims only the two
//!   offsets the instructions spell out (`add r0, r0, #0x28` and
//!   `add r0, r0, #0x94`).

use crate::cxx::string_object::{string_object_c_str, StringObject};
use crate::libc::strcmp::strcmp;

/// Byte offset of the embedded name string object — the original's
/// `add r0, r0, #0x28` @ 0x081346ec.
pub const NAME_OFFSET: usize = 0x28;

/// Byte offset of the name-keyed binding map — the original's
/// `add r0, r0, #0x94` @ 0x081346d0. The container's own header word sits
/// at `+0x10` inside it, which is the `this + 0xa4` the validation walk
/// @ 0x08134938 loads.
pub const BINDING_MAP_OFFSET: usize = 0x94;

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

/// Explicit host-model boundary for the two callees of
/// [`template_binding_map_assign`], neither of which is ported yet.
#[derive(Clone, Copy)]
pub struct TemplateBindingOps {
    /// Original 0x083c2130: copy-assign the binding map at
    /// `this + 0x94` from `source`, returning the destination. A
    /// red-black-tree `operator=`; it self-assignment-guards on
    /// `destination == source`.
    pub assign_map: unsafe extern "C" fn(destination: *mut u8, source: *const u8) -> *mut u8,
    /// Original 0x08134938: walk the freshly assigned binding map and
    /// return 1 only when every bound name validates.
    pub validate_bound_names: unsafe extern "C" fn(this: *mut u8) -> u32,
}

/// Default boundary before 0x083c2130 is ported: the original returns the
/// destination, and a no-op copy is deliberately not a stand-in for the
/// tree assignment.
unsafe extern "C" fn missing_assign_map(destination: *mut u8, _source: *const u8) -> *mut u8 {
    destination
}

/// Default boundary before 0x08134938 is ported. Zero is the original's
/// "some bound name did not validate" answer — the conservative reading
/// while the walk is unavailable.
unsafe extern "C" fn missing_validate_bound_names(_this: *mut u8) -> u32 {
    0
}

/// Wired defaults for [`TEMPLATE_BINDING_OPS`].
pub const DEFAULT_TEMPLATE_BINDING_OPS: TemplateBindingOps = TemplateBindingOps {
    assign_map: missing_assign_map,
    validate_bound_names: missing_validate_bound_names,
};

/// Active model of 0x081346c8's two callees. A later port of either one
/// replaces its default without changing this caller.
pub static mut TEMPLATE_BINDING_OPS: TemplateBindingOps = DEFAULT_TEMPLATE_BINDING_OPS;

#[inline(always)]
unsafe fn assign_map_op() -> unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(TEMPLATE_BINDING_OPS.assign_map))
}

#[inline(always)]
unsafe fn validate_bound_names_op() -> unsafe extern "C" fn(*mut u8) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(TEMPLATE_BINDING_OPS.validate_bound_names))
}

/// template_binding_map_assign — original: `FUN_081346c8` @ 0x081346c8
/// (28 bytes, 116 `bl` call sites and no tail `b`, binary-scanned over
/// `osos.dec`).
///
/// Copy-assigns the object's name-keyed binding map at
/// `this + 0x94` from `source`, then tail-branches to the validation walk
/// over that same map and returns its verdict (1 = every bound name is
/// known). The assignment's own return value is discarded, exactly as the
/// original's `mov r0, r4` discards it. No NULL guard on either argument.
///
/// # Safety
///
/// `this` must point into a readable, writable allocation containing the
/// binding map at byte offset [`BINDING_MAP_OFFSET`], and `source` must
/// satisfy whatever the installed [`TemplateBindingOps::assign_map`]
/// requires.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn template_binding_map_assign(this: *mut u8, source: *const u8) -> u32 {
    assign_map_op()(this.add(BINDING_MAP_OFFSET), source);
    validate_bound_names_op()(this)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::vec::Vec;

    /// Object big enough to hold the name string object at +0x28 and the
    /// binding map at +0x94; the layout beyond those two offsets is
    /// irrelevant to both ports.
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

    static OPS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static mut ASSIGN_CALLS: Vec<(*mut u8, *const u8)> = Vec::new();
    static mut VALIDATE_CALLS: Vec<*mut u8> = Vec::new();
    static mut VALIDATE_RESULT: u32 = 0;

    unsafe extern "C" fn recording_assign(destination: *mut u8, source: *const u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(ASSIGN_CALLS)).push((destination, source));
        destination
    }

    unsafe extern "C" fn recording_validate(this: *mut u8) -> u32 {
        // Ordering evidence: the original assigns before it validates.
        assert_eq!((*core::ptr::addr_of!(ASSIGN_CALLS)).len(), 1);
        (*core::ptr::addr_of_mut!(VALIDATE_CALLS)).push(this);
        core::ptr::addr_of!(VALIDATE_RESULT).read()
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(TEMPLATE_BINDING_OPS)
                    .write_volatile(DEFAULT_TEMPLATE_BINDING_OPS);
            }
        }
    }

    fn ops_bench(validate_result: u32) -> OpsGuard {
        let lock = OPS_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(ASSIGN_CALLS)).clear();
            (*core::ptr::addr_of_mut!(VALIDATE_CALLS)).clear();
            core::ptr::addr_of_mut!(VALIDATE_RESULT).write(validate_result);
            core::ptr::addr_of_mut!(TEMPLATE_BINDING_OPS).write_volatile(TemplateBindingOps {
                assign_map: recording_assign,
                validate_bound_names: recording_validate,
            });
        }
        OpsGuard { _lock: lock }
    }

    #[test]
    fn assign_targets_the_map_member_then_validates_the_whole_object() {
        let _bench = ops_bench(1);
        let mut object = std::vec![0u8; OBJECT_SIZE];
        let source = [0xa5u8; 4];
        let this = object.as_mut_ptr();

        let verdict = unsafe { template_binding_map_assign(this, source.as_ptr()) };

        assert_eq!(verdict, 1);
        unsafe {
            assert_eq!(
                (&(*core::ptr::addr_of!(ASSIGN_CALLS)))[..],
                [(this.add(BINDING_MAP_OFFSET), source.as_ptr())]
            );
            assert_eq!((&(*core::ptr::addr_of!(VALIDATE_CALLS)))[..], [this]);
        }
    }

    #[test]
    fn a_failing_validation_is_returned_verbatim() {
        let _bench = ops_bench(0);
        let mut object = std::vec![0u8; OBJECT_SIZE];

        let verdict =
            unsafe { template_binding_map_assign(object.as_mut_ptr(), core::ptr::null()) };

        assert_eq!(verdict, 0);
    }

    #[test]
    fn the_default_boundary_reports_an_unvalidated_object() {
        let _bench = ops_bench(1);
        unsafe {
            core::ptr::addr_of_mut!(TEMPLATE_BINDING_OPS)
                .write_volatile(DEFAULT_TEMPLATE_BINDING_OPS);
        }
        let mut object = std::vec![0u8; OBJECT_SIZE];

        let verdict =
            unsafe { template_binding_map_assign(object.as_mut_ptr(), core::ptr::null()) };

        assert_eq!(verdict, 0);
    }
}

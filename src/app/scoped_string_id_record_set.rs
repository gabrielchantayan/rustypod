//! Constructor and plain destructor for an unidentified 0x6c-byte application
//! aggregate.
//!
//! `scoped_string_id_record_set_construct` — original: `FUN_081979dc` @
//! **0x081979dc** (**80 bytes: 76 code + the 4-byte literal-pool word @
//! 0x08197a2c**; **7 direct, unconditional `bl` call sites**, no predicated
//! forms, binary-scanned by decoding every ARM `B`/`BL` word in `osos.dec).
//! It plants descriptor 0x08989b60, constructs the 20-byte context scope at
//! +0x04, default-constructs five StringIdRecords at +0x18 through +0x58, and
//! zeroes the trailing word at +0x68.
//!
//! `scoped_string_id_record_set_destroy` — original: `FUN_08197a30` @
//! **0x08197a30** (**68 bytes: 64 code + the 4-byte literal-pool word @
//! 0x08197a70**; **11 direct `bl` call sites**, all unconditional and no
//! predicated forms, binary-scanned by decoding every ARM `B`/`BL` word in
//! `osos.dec`).
//!
//! The record has a descriptor word at +0x00, one 20-byte [`ContextScope`]
//! layout at +0x04, five [`StringIdRecord`] members at +0x18 through +0x58,
//! and an untouched word at +0x68. Its non-deleting destructor reinstalls the
//! literal-pool descriptor `0x08989b60`, destroys the five string/id members
//! in reverse declaration order, drops the context scope, and returns `this`.
//! All constructor and destructor helper calls are direct retailOS calls:
//! `context_scope_init` @ 0x082840e8, `string_id_record_default_construct` @
//! 0x08258c58, `string_id_record_destroy` @ 0x08258c80 five times, and
//! `context_scope_drop` @ 0x08284188 once.
//!
//! The class's semantic identity is not established. The descriptor literal
//! points at the binary string `TransitionAddonI28TSilverMediaListCntlr_GeniusE`;
//! that fact does not establish a class name, so this module and its types name
//! only the proven member layout.
//!
//! Deliberate deviations: the ROM descriptor pointer is represented by the
//! static [`SCOPED_STRING_ID_RECORD_SET_DESCRIPTOR`] rather than an absolute
//! host pointer. `repr(C)` has the retail layout on ARM; its pointer fields are
//! wider on host, so construction and destruction use named members instead of
//! literal byte offsets while preserving the retail call and store order. A
//! target-only volatile read of the `context_scope_drop` function pointer
//! retains its mandatory call: LLVM otherwise sees the empty body and removes
//! it, so the retail `bl` becomes a documented `blx` code-generation
//! deviation.

use crate::app::context_scope::{context_scope_init, CONTEXT_SCOPE_SIZE};
#[cfg(not(target_os = "none"))]
use crate::app::context_scope::context_scope_drop;
use crate::cxx::string_object::{
    string_id_record_default_construct, string_id_record_destroy, StringIdRecord,
};
use core::ptr;
use core::ptr::null_mut;


#[cfg(target_os = "none")]
unsafe extern "C" {
    /// An external declaration retains retailOS's direct `bl` to the empty
    /// destructor, which LLVM would otherwise remove after seeing its body.
    #[link_name = "context_scope_drop"]
    fn context_scope_drop_direct(scope: *mut u8) -> *mut u8;
}


/// ABI of the empty ContextScope destructor at 0x08284188.
#[cfg(target_os = "none")]
type ContextScopeDrop = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Immutable target-only call target. Its volatile read prevents elimination
/// of the retailOS destructor call after the optimizer sees its empty body.
#[cfg(target_os = "none")]
static CONTEXT_SCOPE_DROP_DIRECT: ContextScopeDrop = context_scope_drop_direct;
/// Original descriptor word loaded from the literal pool at 0x08197a70.
pub const SCOPED_STRING_ID_RECORD_SET_DESCRIPTOR_ADDRESS: usize = 0x0898_9b60;

/// The NUL-terminated binary string at
/// [`SCOPED_STRING_ID_RECORD_SET_DESCRIPTOR_ADDRESS`].
pub static SCOPED_STRING_ID_RECORD_SET_DESCRIPTOR: [u8; 48] =
    *b"TransitionAddonI28TSilverMediaListCntlr_GeniusE\0";

/// The object layout proven by the constructor/destructor/copy siblings.
///
/// On ARM this is 0x6c bytes: a descriptor word, a 20-byte context scope,
/// five 0x10-byte [`StringIdRecord`] members, and an untouched trailing word.
#[repr(C)]
pub struct ScopedStringIdRecordSet {
    /// +0x00 — the descriptor word (literal 0x08989b60).
    pub descriptor: *const u8,
    /// +0x04 — a `ContextScope` represented as its five-word byte layout.
    pub scope: [u8; CONTEXT_SCOPE_SIZE],
    /// +0x18 — five string/id records, destroyed from the last to the first.
    pub records: [StringIdRecord; 5],
    /// +0x68 — copied by the sibling copy constructor; untouched here.
    pub trailing_word: u32,
}
/// scoped_string_id_record_set_construct — original: `FUN_081979dc` @
/// 0x081979dc (**80 bytes: 76 code + the 4-byte descriptor literal @
/// 0x08197a2c; 7 direct, unconditional `bl` call sites**, no predicated
/// forms, binary-scanned over every ARM `B`/`BL` word in `osos.dec`).
///
/// Plants the aggregate descriptor, default-constructs its embedded
/// ContextScope with a NULL subject and clear flag, then default-constructs
/// all five StringIdRecord members in ascending declaration order. The final
/// store clears +0x68. The ContextScope's byte-sized flag leaves its three
/// trailing padding bytes untouched. It returns `this` in the ADS constructor
/// convention.
///
/// The original chains its callee results through `add r0,#20` and five
/// `add r0,#16` instructions before deriving `this` for the +0x68 store. The
/// Rust port addresses named members instead so the same stores remain correct
/// on 64-bit hosts, whose pointer-wide fields change the aggregate layout.
///
/// # Safety
///
/// `this` must point to writable raw storage for a
/// [`ScopedStringIdRecordSet`]. The constructor has no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_string_id_record_set_construct(
    this: *mut ScopedStringIdRecordSet,
) -> *mut ScopedStringIdRecordSet {
    ptr::addr_of_mut!((*this).descriptor)
        .write(SCOPED_STRING_ID_RECORD_SET_DESCRIPTOR.as_ptr());

    let scope = ptr::addr_of_mut!((*this).scope).cast::<u8>();
    context_scope_init(scope, null_mut(), 0);

    let records = ptr::addr_of_mut!((*this).records).cast::<StringIdRecord>();
    string_id_record_default_construct(records.add(0));
    string_id_record_default_construct(records.add(1));
    string_id_record_default_construct(records.add(2));
    string_id_record_default_construct(records.add(3));
    string_id_record_default_construct(records.add(4));

    ptr::addr_of_mut!((*this).trailing_word).write(0);
    this
}

/// scoped_string_id_record_set_destroy — original: `FUN_08197a30` @
/// 0x08197a30 (68 bytes: 64 code + literal; 11 unconditional direct `bl`
/// call sites, binary-scanned).
///
/// Reinstalls the aggregate descriptor, destroys `records[4]` through
/// `records[0]`, drops the embedded context scope, and returns `this`. There
/// is no allocation or NULL guard: as on retailOS, a NULL pointer faults on
/// the first descriptor store.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_string_id_record_set_destroy(
    this: *mut ScopedStringIdRecordSet,
) -> *mut ScopedStringIdRecordSet {
    (*this).descriptor = SCOPED_STRING_ID_RECORD_SET_DESCRIPTOR.as_ptr();
    string_id_record_destroy(&mut (*this).records[4]);
    string_id_record_destroy(&mut (*this).records[3]);
    string_id_record_destroy(&mut (*this).records[2]);
    string_id_record_destroy(&mut (*this).records[1]);
    string_id_record_destroy(&mut (*this).records[0]);
    #[cfg(target_os = "none")]
    core::ptr::read_volatile(core::ptr::addr_of!(CONTEXT_SCOPE_DROP_DIRECT))(
        (*this).scope.as_mut_ptr(),
    );
    #[cfg(not(target_os = "none"))]
    context_scope_drop((*this).scope.as_mut_ptr());
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        string_object_release_payload, StringObjectOps, StringObjectVtable,
        StringIdRecordVtable, STRING_ID_RECORD_VTABLE, STRING_OBJECT_OPS,
        STRING_OBJECT_VTABLE,
    };
    use crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK;

    static mut RELEASED: [usize; 5] = [0; 5];
    static mut RELEASE_COUNT: usize = 0;

    unsafe extern "C" fn record_release(string: *mut crate::cxx::string_object::StringObject) {
        RELEASED[RELEASE_COUNT] = string as usize;
        RELEASE_COUNT += 1;
    }

    struct RestoreStringObjectOps;

    impl Drop for RestoreStringObjectOps {
        fn drop(&mut self) {
            unsafe {
                STRING_OBJECT_OPS = StringObjectOps {
                    release_payload: string_object_release_payload,
                };
            }
        }
    }
    #[test]
    fn constructs_every_member_from_dirty_raw_storage() {
        let mut storage = core::mem::MaybeUninit::<ScopedStringIdRecordSet>::uninit();
        unsafe {
            core::ptr::write_bytes(
                storage.as_mut_ptr().cast::<u8>(),
                0xa5,
                core::mem::size_of::<ScopedStringIdRecordSet>(),
            );
            let this = storage.as_mut_ptr();
            assert_eq!(scoped_string_id_record_set_construct(this), this);

            let object = storage.assume_init();
            assert_eq!(
                object.descriptor,
                SCOPED_STRING_ID_RECORD_SET_DESCRIPTOR.as_ptr(),
                "the constructor plants the aggregate descriptor"
            );

            let mut expected_scope = [0; CONTEXT_SCOPE_SIZE];
            expected_scope[..4].copy_from_slice(
                &crate::app::context_scope::CONTEXT_SCOPE_DESCRIPTOR.to_ne_bytes(),
            );
            expected_scope[17..].fill(0xa5);
            assert_eq!(
                object.scope, expected_scope,
                "the embedded scope has a NULL subject and clear flag"
            );
            assert_eq!(object.trailing_word, 0, "the final word is explicitly cleared");
            for record in object.records {
                assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
                assert_eq!(record.string.vtable, &STRING_OBJECT_VTABLE as *const _);
                assert!(record.string.payload.is_null());
                assert_eq!(record.id, -1);
            }
        }
    }


    #[test]
    fn restores_descriptor_and_destroys_members_in_reverse_order() {
        let _lock = STRING_OBJECT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = RestoreStringObjectOps;
        unsafe {
            RELEASED = [0; 5];
            RELEASE_COUNT = 0;
            STRING_OBJECT_OPS = StringObjectOps {
                release_payload: record_release,
            };
        }

        let mut object: ScopedStringIdRecordSet = unsafe { core::mem::zeroed() };
        object.descriptor = 0xdead_beefusize as *const u8;
        object.scope.fill(0xa5);
        object.trailing_word = 0xcafe_f00d;
        for (index, record) in object.records.iter_mut().enumerate() {
            record.vtable = 0x1111_0000usize.wrapping_add(index) as *const StringIdRecordVtable;
            record.string.vtable =
                0x2222_0000usize.wrapping_add(index) as *const StringObjectVtable;
            record.string.payload = 0x3333_0000usize.wrapping_add(index) as *mut u8;
            record.id = i32::MIN.wrapping_add(index as i32);
        }

        let this = &mut object as *mut ScopedStringIdRecordSet;
        let expected_releases = [
            (&mut object.records[4].string) as *mut _ as usize,
            (&mut object.records[3].string) as *mut _ as usize,
            (&mut object.records[2].string) as *mut _ as usize,
            (&mut object.records[1].string) as *mut _ as usize,
            (&mut object.records[0].string) as *mut _ as usize,
        ];
        unsafe {
            assert_eq!(scoped_string_id_record_set_destroy(this), this);
            assert_eq!(RELEASE_COUNT, 5);
            assert_eq!(RELEASED, expected_releases);
        }
        assert_eq!(
            object.descriptor,
            SCOPED_STRING_ID_RECORD_SET_DESCRIPTOR.as_ptr(),
            "the literal-pool descriptor is replanted first"
        );
        assert_eq!(object.scope, [0xa5; CONTEXT_SCOPE_SIZE]);
        assert_eq!(object.trailing_word, 0xcafe_f00d);
        for (index, record) in object.records.iter().enumerate() {
            assert_eq!(record.vtable, &STRING_ID_RECORD_VTABLE as *const _);
            assert_eq!(record.string.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert_eq!(record.string.payload as usize, 0x3333_0000usize + index);
            assert_eq!(record.id, i32::MIN.wrapping_add(index as i32));
        }
    }
}

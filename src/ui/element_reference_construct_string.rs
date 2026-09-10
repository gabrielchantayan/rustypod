//! Constructing a StringObject from a resolve-gated UI element reference.
//!
//! - `ui_element_reference_construct_string` — original: `FUN_082a6554` @
//!   `0x082a6554` (144 bytes: 136 code plus the two literal-pool words at
//!   `0x082a65dc`/`0x082a65e0`; 14 direct `bl` call sites, all unconditional).
//!
//! The reference is the same vtable-headed UI element reference used by the
//! neighboring 0x082a6524 persistent-ID getter. Its +0x0c resolve slot gates
//! both later paths. A resolved reference takes one of two routes selected by
//! its opaque +0x20 virtual slot: zero extracts a bounded UTF-16 label from
//! the target word at +0x04; nonzero looks up resource `0x0dad06c2` in the
//! resource chain held by the global word at 0x089cc870. Both routes assign
//! the result to a freshly constructed StringObject.
//!
//! The identities of the +0x0c and +0x20 virtual methods are not established.
//! The static +0x0c table word is 0x0826acd8, a selector/implementation data
//! pair rather than a function entry; this port dispatches the raw slots and
//! deliberately does not invent callee names.

use core::mem::MaybeUninit;
use core::ptr;

use crate::app::resource_chain::{resource_chain_find_string, ResourceProvider};
use crate::cxx::string_object::{
    string_default_construct, string_object_assign_payload, string_object_assign_utf16, StringObject,
};

/// Firmware global word holding the resource-provider chain head for the
/// fallback path (`ldr r0, [0x082a65dc]` / `ldr r0, [r0]`).
pub const UI_ELEMENT_REFERENCE_RESOURCE_CHAIN_GLOBAL: usize = 0x089c_c870;

/// Resource ID passed to `resource_chain_find_string` on the +0x20 nonzero
/// path (the literal-pool word at 0x082a65e0).
pub const UI_ELEMENT_REFERENCE_FALLBACK_STRING_ID: u32 = 0x0dad_06c2;

/// The reference's resolve slot (`ldr r1, [vtable, #0xc]`).
const RESOLVE_SLOT_WORD: usize = 3;
/// The opaque route-selection slot (`ldr r1, [vtable, #0x20]`).
const STRING_ROUTE_SLOT_WORD: usize = 8;

/// Native-width host representation of the +0x0c virtual call.
type ResolveSlot = unsafe extern "C" fn(*const u8) -> u32;
/// Native-width host representation of the +0x20 virtual call.
type StringRouteSlot = unsafe extern "C" fn(*const u8) -> u32;
/// Unported 0x080544dc: writes a u16 count followed by at most 255 UTF-16 units.
type ElementUtf16Extract = unsafe extern "C" fn(*mut u8, *mut u16);

/// The two target-width words read by this function. `repr(C)` keeps them
/// adjacent at +0x0/+0x4 on ARM; host fixtures map both words below 4 GiB.
#[repr(C)]
struct UiElementReference {
    vtable: u32,
    target: u32,
}

/// The original reserves 0x204 stack bytes and passes the first halfword at
/// `sp + 4` to 0x080544dc; that callee writes its UTF-16 text at +2.
#[repr(C)]
struct Utf16ExtractScratch {
    frame_pad: u32,
    unit_count: u16,
    units: [MaybeUninit<u16>; 255],
}

/// Calls the unported UTF-16 extractor at 0x080544dc on firmware. Host tests
/// replace the active boundary below; its host default deliberately produces
/// the extractor's initialized empty result.
unsafe extern "C" fn firmware_element_utf16_extract(target: *mut u8, out: *mut u16) {
    #[cfg(target_os = "none")]
    {
        let extract: ElementUtf16Extract = core::mem::transmute(0x0805_44dcusize);
        extract(target, out);
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = target;
        out.write(0);
    }
}

/// Boundary for the only direct unported callee, 0x080544dc. Its firmware
/// default calls the fixed load address; host tests replace it to provide the
/// opaque target's extracted UTF-16 content.
static mut ELEMENT_UTF16_EXTRACT: ElementUtf16Extract = firmware_element_utf16_extract;

#[inline(always)]
unsafe fn element_utf16_extract_op() -> ElementUtf16Extract {
    ptr::read_volatile(ptr::addr_of!(ELEMENT_UTF16_EXTRACT))
}

/// Gets the fallback resource chain head. On firmware this is the contents of
/// the literal-pool global; a host cannot map that global page, so the test
/// model supplies the equivalent pointer through a crate static.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resource_chain_head() -> *mut ResourceProvider {
    ptr::read_volatile(UI_ELEMENT_REFERENCE_RESOURCE_CHAIN_GLOBAL as *const *mut ResourceProvider)
}

#[cfg(not(target_os = "none"))]
static mut HOST_RESOURCE_CHAIN_HEAD: *mut ResourceProvider = ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resource_chain_head() -> *mut ResourceProvider {
    ptr::read_volatile(ptr::addr_of!(HOST_RESOURCE_CHAIN_HEAD))
}

/// ui_element_reference_construct_string — original: `FUN_082a6554` @
/// `0x082a6554` (144 bytes, exact: 136 bytes of code from 0x082a6554 through
/// 0x082a65d8 plus literal-pool words at 0x082a65dc/0x082a65e0; the next
/// separately linked function opens `push {r4,lr}` at 0x082a65e4). **14 direct
/// `bl` call sites**, all unconditional plain `bl`, zero predicated forms and
/// zero direct `b` references, verified by decoding every ARM B/BL word in
/// `osos.dec`.
///
/// Default-construct `out` before inspecting `reference`. A zero result from
/// the reference vtable's +0x0c resolve slot returns that empty StringObject
/// without reading its target or invoking the +0x20 slot. Otherwise, a zero
/// +0x20 result calls the unported extractor 0x080544dc with `reference+0x4`'s
/// target word and a 0x200-byte UTF-16 scratch region, then assigns precisely
/// the returned u16 count through `string_object_assign_utf16`. A nonzero
/// +0x20 result instead looks up ID 0x0dad06c2 from the global resource chain
/// and assigns the returned C string, including the NULL lookup result.
///
/// Deliberate deviations: the vtable slots are native-width function pointers
/// in host fixtures although firmware slot spacing is target words; the
/// firmware resource-chain global is modeled by `HOST_RESOURCE_CHAIN_HEAD` on
/// host; and direct callee 0x080544dc remains an explicit boundary whose ARM
/// default calls its fixed address. The virtual callee identities remain
/// unestablished, so this port preserves raw dispatch rather than naming them.
///
/// # Safety
///
/// `out` must point to writable StringObject storage. `reference` must expose
/// readable target-width words at +0/+4 and native-callable fixture slots at
/// target words +3/+8. A resolved zero-route reference must supply a target
/// acceptable to 0x080544dc; a nonzero route requires a valid provider chain
/// in the firmware global when the resource lookup traverses it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_construct_string(
    out: *mut StringObject,
    reference: *const u8,
) {
    string_default_construct(out);

    let reference_words = reference.cast::<UiElementReference>();
    let vtable = (*reference_words).vtable as usize as *const u8;
    let resolve = vtable.add(RESOLVE_SLOT_WORD * core::mem::size_of::<u32>())
        .cast::<ResolveSlot>()
        .read();
    if resolve(reference) == 0 {
        return;
    }

    let route = vtable.add(STRING_ROUTE_SLOT_WORD * core::mem::size_of::<u32>())
        .cast::<StringRouteSlot>()
        .read();
    if route(reference) == 0 {
        let mut scratch = MaybeUninit::<Utf16ExtractScratch>::uninit();
        let scratch_ptr = scratch.as_mut_ptr();
        element_utf16_extract_op()(
            (*reference_words).target as usize as *mut u8,
            ptr::addr_of_mut!((*scratch_ptr).unit_count),
        );
        string_object_assign_utf16(
            out,
            ptr::addr_of!((*scratch_ptr).units).cast::<u16>(),
            i32::from((*scratch_ptr).unit_count),
        );
    } else {
        let text = resource_chain_find_string(
            resource_chain_head(),
            UI_ELEMENT_REFERENCE_FALLBACK_STRING_ID,
        );
        string_object_assign_payload(out, text);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::resource_chain::{
        ResourceFindFn, ResourceKind, ResourceProviderVTable, ResourceReadFn, ResourceWriteFn,
    };
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS,
        STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_VTABLE,
    };
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVE_RESULT: u32 = 0;
    static mut ROUTE_RESULT: u32 = 0;
    static mut RESOLVE_CALLS: u32 = 0;
    static mut ROUTE_CALLS: u32 = 0;
    static mut EXTRACT_CALLS: u32 = 0;
    static mut EXTRACT_TARGET: *mut u8 = ptr::null_mut();
    static mut ALLOCATE_CALLS: u32 = 0;
    static mut CLEAR_CALLS: u32 = 0;
    static mut LAST_RESOURCE_ID: u32 = 0;
    static mut EXPECTED_ALLOCATION_SIZE: usize = 0;
    static mut ALLOCATION: [u8; 32] = [0; 32];
    static FALLBACK_TEXT: [u8; 9] = *b"fallback\0";

    unsafe extern "C" fn resolve_stub(_reference: *const u8) -> u32 {
        RESOLVE_CALLS += 1;
        RESOLVE_RESULT
    }

    unsafe extern "C" fn route_stub(_reference: *const u8) -> u32 {
        ROUTE_CALLS += 1;
        ROUTE_RESULT
    }

    unsafe extern "C" fn extract_stub(target: *mut u8, out: *mut u16) {
        EXTRACT_CALLS += 1;
        EXTRACT_TARGET = target;
        out.write(2);
        out.add(1).write(b'H' as u16);
        out.add(2).write(b'i' as u16);
    }

    unsafe extern "C" fn allocate_stub(
        this: *mut StringObject,
        requested: usize,
        flags: u32,
    ) -> *mut u8 {
        assert_eq!(requested, EXPECTED_ALLOCATION_SIZE);
        assert_eq!(flags, 0);
        ALLOCATE_CALLS += 1;
        (*this).payload = ptr::addr_of_mut!(ALLOCATION).cast::<u8>();
        ptr::addr_of_mut!(ALLOCATION).cast::<u8>()
    }

    unsafe extern "C" fn clear_stub(_this: *mut StringObject) {
        CLEAR_CALLS += 1;
    }

    unsafe extern "C" fn find_stub(
        _provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
        found: *mut *mut u8,
    ) -> u32 {
        LAST_RESOURCE_ID = id;
        if kind == ResourceKind::STRING && id == UI_ELEMENT_REFERENCE_FALLBACK_STRING_ID {
            found.write(FALLBACK_TEXT.as_ptr() as *mut u8);
            1
        } else {
            0
        }
    }

    unsafe extern "C" fn unused_read(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn unused_write(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
        _value: u32,
        _flags: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn replacement_permits(
        _provider: *mut ResourceProvider,
        _replacement: *mut ResourceProvider,
    ) -> u32 {
        1
    }

    static PROVIDER_VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22],
        read: unused_read as ResourceReadFn,
        slot_5c: None,
        replacement_allowed: replacement_permits,
        find: find_stub as ResourceFindFn,
        write: unused_write as ResourceWriteFn,
    };

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ELEMENT_REFERENCE_CONSTRUCT_STRING,
                0x1000,
            )
            .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    unsafe fn reference() -> *mut u8 {
        try_slab().expect("fixture slab checked by the caller's skip guard")
    }

    unsafe fn vtable() -> *mut u8 {
        reference().add(0x100)
    }

    unsafe fn target() -> *mut u8 {
        reference().add(0x400)
    }

    unsafe fn prepare(resolve: u32, route: u32) {
        RESOLVE_RESULT = resolve;
        ROUTE_RESULT = route;
        RESOLVE_CALLS = 0;
        ROUTE_CALLS = 0;
        EXTRACT_CALLS = 0;
        EXTRACT_TARGET = ptr::null_mut();
        ALLOCATE_CALLS = 0;
        CLEAR_CALLS = 0;
        LAST_RESOURCE_ID = 0;
        EXPECTED_ALLOCATION_SIZE = if route == 0 { 3 } else { FALLBACK_TEXT.len() };
        ALLOCATION = [0; 32];

        reference().cast::<UiElementReference>().write(UiElementReference {
            vtable: vtable() as u32,
            target: target() as u32,
        });
        vtable()
            .add(RESOLVE_SLOT_WORD * core::mem::size_of::<u32>())
            .cast::<ResolveSlot>()
            .write(resolve_stub);
        vtable()
            .add(STRING_ROUTE_SLOT_WORD * core::mem::size_of::<u32>())
            .cast::<StringRouteSlot>()
            .write(route_stub);
        ptr::addr_of_mut!(ELEMENT_UTF16_EXTRACT).write_volatile(extract_stub);
        ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(StringObjectAssignCstrOps {
            allocate_payload: allocate_stub,
            clear_payload: clear_stub,
        });
    }

    struct ResetGuards;

    impl Drop for ResetGuards {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(ELEMENT_UTF16_EXTRACT).write_volatile(firmware_element_utf16_extract);
                ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS)
                    .write_volatile(DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS);
                ptr::addr_of_mut!(HOST_RESOURCE_CHAIN_HEAD).write_volatile(ptr::null_mut());
            }
        }
    }

    #[test]
    fn failed_resolve_leaves_out_constructed_without_reading_other_paths() {
        let _assign_lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fixture_lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_construct_string");
            return;
        }
        let _reset = ResetGuards;
        unsafe {
            prepare(0, 1);
            let mut out = MaybeUninit::<StringObject>::uninit();
            ui_element_reference_construct_string(out.as_mut_ptr(), reference());
            let out = out.assume_init();

            assert!(core::ptr::eq(out.vtable, &STRING_OBJECT_VTABLE));
            assert!(out.payload.is_null());
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(ROUTE_CALLS, 0);
            assert_eq!(EXTRACT_CALLS, 0);
            assert_eq!(ALLOCATE_CALLS, 0);
            assert_eq!(CLEAR_CALLS, 0);
        }
    }

    #[test]
    fn resolved_zero_route_extracts_bounded_utf16_from_target() {
        let _assign_lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fixture_lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_construct_string");
            return;
        }
        let _reset = ResetGuards;
        unsafe {
            prepare(0xffff_ffff, 0);
            let mut out = MaybeUninit::<StringObject>::uninit();
            ui_element_reference_construct_string(out.as_mut_ptr(), reference());

            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(ROUTE_CALLS, 1);
            assert_eq!(EXTRACT_CALLS, 1);
            assert_eq!(EXTRACT_TARGET, target());
            assert_eq!(ALLOCATE_CALLS, 1);
            assert_eq!(CLEAR_CALLS, 0);
            assert_eq!(&ALLOCATION[..3], b"Hi\0");
        }
    }

    #[test]
    fn resolved_nonzero_route_assigns_the_fallback_resource_string() {
        let _assign_lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fixture_lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_construct_string");
            return;
        }
        let _reset = ResetGuards;
        unsafe {
            prepare(1, 7);
            let mut provider = ResourceProvider {
                vtable: &PROVIDER_VTABLE,
                state_below_next: [ptr::null_mut(); 4],
                next: ptr::null_mut(),
            };
            ptr::addr_of_mut!(HOST_RESOURCE_CHAIN_HEAD).write_volatile(&mut provider);
            let mut out = MaybeUninit::<StringObject>::uninit();
            ui_element_reference_construct_string(out.as_mut_ptr(), reference());

            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(ROUTE_CALLS, 1);
            assert_eq!(EXTRACT_CALLS, 0);
            assert_eq!(LAST_RESOURCE_ID, UI_ELEMENT_REFERENCE_FALLBACK_STRING_ID);
            assert_eq!(ALLOCATE_CALLS, 1);
            assert_eq!(&ALLOCATION[..9], b"fallback\0");
        }
    }

    #[test]
    fn unresolved_fallback_resource_dispatches_string_clear() {
        let _assign_lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _fixture_lock = FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::element_reference_construct_string");
            return;
        }
        let _reset = ResetGuards;
        unsafe {
            prepare(1, 1);
            let mut out = MaybeUninit::<StringObject>::uninit();
            ui_element_reference_construct_string(out.as_mut_ptr(), reference());

            assert_eq!(ROUTE_CALLS, 1);
            assert_eq!(EXTRACT_CALLS, 0);
            assert_eq!(ALLOCATE_CALLS, 0);
            assert_eq!(CLEAR_CALLS, 1);
        }
    }
}

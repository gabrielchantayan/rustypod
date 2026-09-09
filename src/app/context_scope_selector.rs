//! `context_scope_assign_selector` — original: `FUN_08173878` @ `0x08173878`
//! (**208 bytes exactly**, `0x08173878..0x08173948`).
//!
//! Raw ARM decoding, rather than Ghidra's extent, finds the next separately
//! entered function at `0x08173948` (`push {r4-r11,lr}`). Decoding every ARM
//! B/BL word in `osos.dec` finds **13 direct callers**, all unconditional
//! `bl` (cond=AL), with zero predicated forms and zero plain-`b` tail callers:
//! `0x0817697c`, `0x08176ab4`, `0x08176e1c`, `0x08232738`, `0x08232844`,
//! `0x08232a8c`, `0x08232c20`, `0x08232cc4`, `0x082375ec`, `0x082376e0`,
//! `0x08237744`, `0x0823787c`, and `0x08239b4c`.
//!
//! # Algorithm
//!
//! A selector of `-1` directly initializes `scope` as an empty context scope.
//! Otherwise the source's handle at `+0x18` is unwrapped and virtual slot
//! `+0x1c0` writes a 16-byte handle. When byte `+0x84c` is set, the source's
//! current-selector virtual slot `+0x1bc` is compared to the element-4 vector
//! size at `+0x840`; a mismatch refreshes that selector map through the direct,
//! still-unported `0x08177604`, then re-unwraps the handle and replaces the
//! selector with `vector[selector]`. The produced handle initializes a stack
//! context scope, which is memberwise assigned to `scope`; its destructor is
//! the ported empty `bx lr` body.
//!
//! The non-`-1` assignment deliberately does not overwrite `scope +0x00`
//! (the descriptor) and writes only byte `+0x10`; pre-existing upper bytes
//! of that final word survive. The `-1` constructor instead plants the
//! descriptor and its byte store likewise preserves the upper three bytes.
//!
//! The virtual slots' concrete identities are not recovered. They are modeled
//! only by their verified ABI and offsets; the target dispatches their raw
//! ARM vtable words, while the host uses native-width structural fixtures.
//!
//! # Deliberate deviations
//!
//! The non-`-1` ARM path returns its now-dead stack temporary in `r0` after
//! the empty destructor, while the `-1` tail path returns `scope`. All 13
//! callers discard it, so this Rust port deliberately exposes the stable,
//! recovered operation as `void` rather than exporting a dangling result.
//! The direct refresh helper `0x08177604` is unported: target builds call that
//! verified address, and host builds inject only that edge through
//! [`ContextScopeSelectorOps`].

use crate::app::context_scope::{
    context_scope_assign, context_scope_drop, context_scope_init,
    context_scope_init_from_handle, CONTEXT_SCOPE_SIZE,
};
#[cfg(target_os = "none")]
use crate::cxx::handle::handle_deref_or_null;
use crate::cxx::templates::vector_size_elem4_alias_7a48;
#[cfg(not(target_os = "none"))]
use crate::cxx::templates::VectorBounds;

const SOURCE_HANDLE_OFFSET: usize = 0x18;
const SOURCE_SELECTOR_MAP_OFFSET: usize = 0x840;
const SOURCE_SELECTOR_MAP_READY_OFFSET: usize = 0x84c;
const OBJECT_VTABLE_CURRENT_SELECTOR_WORD: usize = 0x1bc / 4;
const OBJECT_VTABLE_MAKE_HANDLE_WORD: usize = 0x1c0 / 4;
const REFRESH_SELECTOR_MAP_ADDRESS: usize = 0x0817_7604;

/// The host representation of the two virtual slots this port reaches.
///
/// On target they are vtable words 111 and 112 (`+0x1bc` and `+0x1c0`).
/// Native-width function pointers make the host fixture deliberately wider;
/// it represents the slot roles without truncating host pointers.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostContextScopeSelectorVtable {
    pub unresolved_000_to_1b8: [usize; OBJECT_VTABLE_CURRENT_SELECTOR_WORD],
    pub current_selector: unsafe extern "C" fn(*mut u8) -> i32,
    pub make_context_handle: unsafe extern "C" fn(*mut u8, *mut u8, u32),
}

/// Host object whose first field supplies [`HostContextScopeSelectorVtable`].
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostContextScopeSelectorObject {
    pub vtable: *const HostContextScopeSelectorVtable,
}

/// Host structural fixture for the three source members this function reads.
///
/// `handle_cell` has the same two-level indirection as the firmware handle at
/// target `+0x18`. `selector_map` and `selector_map_ready` model target
/// `+0x840` and `+0x84c`; native pointers intentionally widen only on host.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostContextScopeSelectorSource {
    pub handle_cell: *mut *mut u8,
    pub selector_map: VectorBounds,
    pub selector_map_ready: u8,
}

/// ABI of the direct map-refresh helper at `0x08177604`.
pub type ContextScopeSelectorRefresh = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn firmware_refresh_selector_map(source: *mut u8) {
    let refresh: ContextScopeSelectorRefresh = core::mem::transmute(REFRESH_SELECTOR_MAP_ADDRESS);
    refresh(source);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh_selector_map(_source: *mut u8) {
    panic!("context_scope_assign_selector requires refresh helper 0x08177604")
}

/// Host replacement for the one direct, unported refresh call.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ContextScopeSelectorOps {
    pub refresh_selector_map: ContextScopeSelectorRefresh,
}

/// Default host operations fault if the stale-map path is exercised without a
/// test-provided model. The clear-map path needs no direct helper.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_CONTEXT_SCOPE_SELECTOR_OPS: ContextScopeSelectorOps = ContextScopeSelectorOps {
    refresh_selector_map: missing_refresh_selector_map,
};

/// Host-side seam for the direct `0x08177604` call; target builds do not read
/// this static and always call the firmware address.
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_SCOPE_SELECTOR_OPS: ContextScopeSelectorOps =
    DEFAULT_CONTEXT_SCOPE_SELECTOR_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn firmware_refresh_selector_map(source: *mut u8) {
    let refresh = core::ptr::read_volatile(core::ptr::addr_of!(
        CONTEXT_SCOPE_SELECTOR_OPS.refresh_selector_map
    ));
    refresh(source);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn source_object(source: *mut u8) -> *mut u8 {
    handle_deref_or_null(source.add(SOURCE_HANDLE_OFFSET).cast::<*const *mut u8>())
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn source_object(source: *mut u8) -> *mut u8 {
    let source = source.cast::<HostContextScopeSelectorSource>();
    let cell = core::ptr::read_volatile(core::ptr::addr_of!((*source).handle_cell));
    if cell.is_null() {
        core::ptr::null_mut()
    } else {
        cell.read()
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn current_selector(object: *mut u8) -> i32 {
    let vtable = object.cast::<u32>().read();
    let method: unsafe extern "C" fn(*mut u8) -> i32 = core::mem::transmute(
        (vtable as *const u32).add(OBJECT_VTABLE_CURRENT_SELECTOR_WORD).read() as usize,
    );
    method(object)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn current_selector(object: *mut u8) -> i32 {
    let object = object.cast::<HostContextScopeSelectorObject>();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*object).vtable));
    ((*vtable).current_selector)(object.cast())
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn make_context_handle(handle: *mut u8, object: *mut u8, selector: u32) {
    let vtable = object.cast::<u32>().read();
    let method: unsafe extern "C" fn(*mut u8, *mut u8, u32) = core::mem::transmute(
        (vtable as *const u32).add(OBJECT_VTABLE_MAKE_HANDLE_WORD).read() as usize,
    );
    method(handle, object, selector);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn make_context_handle(handle: *mut u8, object: *mut u8, selector: u32) {
    let object = object.cast::<HostContextScopeSelectorObject>();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*object).vtable));
    ((*vtable).make_context_handle)(handle, object.cast(), selector);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn selector_map_size(source: *mut u8) -> i32 {
    vector_size_elem4_alias_7a48(source.add(SOURCE_SELECTOR_MAP_OFFSET).cast())
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn selector_map_size(source: *mut u8) -> i32 {
    vector_size_elem4_alias_7a48(core::ptr::addr_of!((*source.cast::<HostContextScopeSelectorSource>()).selector_map))
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn selector_map_entry(source: *mut u8, selector: i32) -> u32 {
    let map = source.add(SOURCE_SELECTOR_MAP_OFFSET).cast::<u32>().read() as usize as *const u32;
    map.offset(selector as isize).read()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn selector_map_entry(source: *mut u8, selector: i32) -> u32 {
    let map = core::ptr::read_volatile(core::ptr::addr_of!(
        (*source.cast::<HostContextScopeSelectorSource>()).selector_map.begin
    )) as *const u32;
    map.offset(selector as isize).read()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn selector_map_ready(source: *mut u8) -> bool {
    source.add(SOURCE_SELECTOR_MAP_READY_OFFSET).read() != 0
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn selector_map_ready(source: *mut u8) -> bool {
    (*source.cast::<HostContextScopeSelectorSource>()).selector_map_ready != 0
}

/// context_scope_assign_selector — original: `FUN_08173878` @ `0x08173878`
/// (**208 bytes**, 13 direct incoming `bl` call sites, all unconditional).
///
/// Assigns `scope` from the context handle selected by `selector` in `source`.
/// `selector == -1` initializes an empty scope; any other value is passed
/// unvalidated to either the object's handle-maker virtual slot or its
/// selector map, exactly as the ARM body does. A stale ready map is refreshed
/// when the object's current-selector slot differs from that map's element
/// count, and the object handle is deliberately reloaded after refresh.
///
/// # Safety
/// `scope` must name [`CONTEXT_SCOPE_SIZE`] writable, aligned bytes. `source`,
/// its nested handle, virtual object/vtable, and map (when ready) must satisfy
/// every unguarded firmware read and dispatch above. A stale ready map also
/// requires the direct refresh helper at `0x08177604`. Neither `source` nor a
/// non-`-1` selector is NULL- or bounds-checked by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_scope_assign_selector(
    scope: *mut u8,
    source: *mut u8,
    selector: i32,
) {
    if selector == -1 {
        context_scope_init(scope, core::ptr::null_mut(), 0);
        return;
    }

    let mut handle = [0u32; 4];
    if selector_map_ready(source) {
        let object = source_object(source);
        if current_selector(object) != selector_map_size(source) {
            firmware_refresh_selector_map(source);
        }
        let mapped_selector = selector_map_entry(source, selector);
        make_context_handle(handle.as_mut_ptr().cast(), source_object(source), mapped_selector);
    } else {
        make_context_handle(handle.as_mut_ptr().cast(), source_object(source), selector as u32);
    }

    let mut temporary_scope = [0u32; CONTEXT_SCOPE_SIZE / core::mem::size_of::<u32>()];
    context_scope_init_from_handle(temporary_scope.as_mut_ptr().cast(), handle.as_ptr().cast(), 0);
    context_scope_assign(scope, temporary_scope.as_ptr().cast());
    context_scope_drop(temporary_scope.as_mut_ptr().cast());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::context_scope::{APP_ROOT_OBJECT, CONTEXT_SCOPE_DESCRIPTOR};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, APP_ROOT_TEST_LOCK};
    use std::sync::LazyLock;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static SUBJECT_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CONTEXT_SCOPE_SELECTOR, 0x3000).map(|pointer| pointer as usize)
    });

    static mut CURRENT_RESULT: i32 = 0;
    static mut CURRENT_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut MAKE_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut MAKE_SELECTOR: u32 = 0;
    static mut MAKE_CALLS: u32 = 0;
    static mut HANDLE_TAG: u8 = 0;
    static mut HANDLE_SUBJECT: u32 = 0;
    static mut REFRESH_CALLS: u32 = 0;
    static mut REFRESH_OBJECT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_current_selector(object: *mut u8) -> i32 {
        CURRENT_OBJECT = object;
        CURRENT_RESULT
    }

    unsafe extern "C" fn record_make_context_handle(handle: *mut u8, object: *mut u8, selector: u32) {
        MAKE_OBJECT = object;
        MAKE_SELECTOR = selector;
        MAKE_CALLS += 1;
        handle.cast::<u32>().write(0);
        handle.add(4).write(HANDLE_TAG);
        handle.cast::<u32>().add(2).write(HANDLE_SUBJECT);
        handle.cast::<u32>().add(3).write(0);
    }

    static VTABLE: HostContextScopeSelectorVtable = HostContextScopeSelectorVtable {
        unresolved_000_to_1b8: [0; OBJECT_VTABLE_CURRENT_SELECTOR_WORD],
        current_selector: record_current_selector,
        make_context_handle: record_make_context_handle,
    };

    unsafe extern "C" fn refresh_and_replace_object(source: *mut u8) {
        REFRESH_CALLS += 1;
        let source = source.cast::<HostContextScopeSelectorSource>();
        let cell = (*source).handle_cell;
        cell.write(REFRESH_OBJECT);
    }

    fn reset_recording() {
        unsafe {
            CURRENT_RESULT = 0;
            CURRENT_OBJECT = core::ptr::null_mut();
            MAKE_OBJECT = core::ptr::null_mut();
            MAKE_SELECTOR = 0;
            MAKE_CALLS = 0;
            HANDLE_TAG = 0;
            HANDLE_SUBJECT = 0;
            REFRESH_CALLS = 0;
            REFRESH_OBJECT = core::ptr::null_mut();
            CONTEXT_SCOPE_SELECTOR_OPS = ContextScopeSelectorOps {
                refresh_selector_map: refresh_and_replace_object,
            };
        }
    }

    fn scope_words(scope: &[u32; 5]) -> [u32; 5] {
        *scope
    }

    #[test]
    fn minus_one_initializes_an_empty_scope_without_reading_source() {
        let _test_guard = TEST_LOCK.lock();
        let _root_guard = APP_ROOT_TEST_LOCK.lock();
        reset_recording();
        let mut scope = [u32::MAX; 5];

        unsafe { context_scope_assign_selector(scope.as_mut_ptr().cast(), core::ptr::null_mut(), -1) };

        assert_eq!(scope_words(&scope), [CONTEXT_SCOPE_DESCRIPTOR, 0, 0, 0, 0xffff_ff00]);
        unsafe { assert_eq!(MAKE_CALLS, 0) };
    }

    #[test]
    fn clear_selector_map_forwards_selector_to_virtual_handle_maker() {
        let _test_guard = TEST_LOCK.lock();
        let _root_guard = APP_ROOT_TEST_LOCK.lock();
        reset_recording();
        let mut object = HostContextScopeSelectorObject { vtable: &VTABLE };
        let mut cell = (&mut object as *mut HostContextScopeSelectorObject).cast::<u8>();
        let mut source = HostContextScopeSelectorSource {
            handle_cell: &mut cell,
            selector_map: VectorBounds { begin: core::ptr::null_mut(), end: core::ptr::null_mut() },
            selector_map_ready: 0,
        };
        let mut scope = [0xa5a5_a5a5u32; 5];

        unsafe { context_scope_assign_selector(scope.as_mut_ptr().cast(), (&mut source as *mut HostContextScopeSelectorSource).cast(), 7) };

        unsafe {
            assert_eq!(MAKE_CALLS, 1);
            assert_eq!(MAKE_OBJECT, (&mut object as *mut HostContextScopeSelectorObject).cast());
            assert_eq!(MAKE_SELECTOR, 7);
            assert_eq!(REFRESH_CALLS, 0);
        }
        assert_eq!(scope_words(&scope), [0xa5a5_a5a5, 0, 0, 0, 0xa5a5_a500]);
    }

    #[test]
    fn stale_ready_map_refreshes_then_reresolves_object_and_maps_selector() {
        let _test_guard = TEST_LOCK.lock();
        let _root_guard = APP_ROOT_TEST_LOCK.lock();
        reset_recording();
        let mut old_object = HostContextScopeSelectorObject { vtable: &VTABLE };
        let mut replacement_object = HostContextScopeSelectorObject { vtable: &VTABLE };
        let mut cell = (&mut old_object as *mut HostContextScopeSelectorObject).cast::<u8>();
        let selectors = [0x11u32, 0xfeed_beefu32];
        let begin = selectors.as_ptr().cast_mut().cast::<u8>();
        let mut source = HostContextScopeSelectorSource {
            handle_cell: &mut cell,
            selector_map: VectorBounds { begin, end: unsafe { begin.add(core::mem::size_of_val(&selectors)) } },
            selector_map_ready: 1,
        };
        let mut scope = [0xa5a5_a5a5u32; 5];
        unsafe {
            CURRENT_RESULT = 0;
            REFRESH_OBJECT = (&mut replacement_object as *mut HostContextScopeSelectorObject).cast();
            context_scope_assign_selector(scope.as_mut_ptr().cast(), (&mut source as *mut HostContextScopeSelectorSource).cast(), 1);
            assert_eq!(CURRENT_OBJECT, (&mut old_object as *mut HostContextScopeSelectorObject).cast());
            assert_eq!(REFRESH_CALLS, 1);
            assert_eq!(MAKE_OBJECT, (&mut replacement_object as *mut HostContextScopeSelectorObject).cast());
            assert_eq!(MAKE_SELECTOR, 0xfeed_beef);
        }
        assert_eq!(scope_words(&scope), [0xa5a5_a5a5, 0, 0, 0, 0xa5a5_a500]);
    }

    #[test]
    fn non_null_handle_subject_is_captured_through_context_scope_constructor() {
        let _test_guard = TEST_LOCK.lock();
        let _root_guard = APP_ROOT_TEST_LOCK.lock();
        reset_recording();
        let Some(base) = *SUBJECT_FIXTURE else {
            note_missing_u32_fixture("context_scope_selector subject capture");
            return;
        };
        let base = base as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, 0x3000);
            let context = base.add(0x1000);
            let subject = base.add(0x2000);
            base.add(0x30).cast::<u32>().write(context as usize as u32);
            context.add(0xf60).cast::<u32>().write(0);
            APP_ROOT_OBJECT = base;
            HANDLE_TAG = 1;
            HANDLE_SUBJECT = subject as usize as u32;

            let mut object = HostContextScopeSelectorObject { vtable: &VTABLE };
            let mut cell = (&mut object as *mut HostContextScopeSelectorObject).cast::<u8>();
            let mut source = HostContextScopeSelectorSource {
                handle_cell: &mut cell,
                selector_map: VectorBounds { begin: core::ptr::null_mut(), end: core::ptr::null_mut() },
                selector_map_ready: 0,
            };
            let mut scope = [0xa5a5_a5a5u32; 5];
            context_scope_assign_selector(scope.as_mut_ptr().cast(), (&mut source as *mut HostContextScopeSelectorSource).cast(), 3);
            APP_ROOT_OBJECT = core::ptr::null_mut();

            assert_eq!(MAKE_SELECTOR, 3);
            assert_eq!(scope_words(&scope), [
                0xa5a5_a5a5,
                subject as usize as u32,
                context as usize as u32,
                0,
                0xa5a5_a500,
            ]);
        }
    }
}

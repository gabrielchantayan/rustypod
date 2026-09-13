//! Releasing a completed UI operation's owned resources.
//!
//! - `ui_operation_destroy` — original: `FUN_0816f050` @ `0x0816f050`
//!   (68 bytes; 7 direct `bl` call sites, all unconditional).

use crate::app::context_scope::context_scope_drop;
use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::runtime::malloc_rt::free;
use crate::ui::element_reference::ui_element_reference_is_current;

/// Target word index of the trailing two-word string object.
const STRING_OBJECT_WORD_INDEX: usize = 17;

/// Prefix through word +0x40 of the operation allocation. The trailing string
/// object begins at word 17; it stays outside this definition because that
/// target object has 4-byte pointers but its host representation has 8-byte
/// pointers.
#[repr(C)]
pub struct UiOperationPrefix {
    _base: [u32; 5],
    element_reference: [u32; 4],
    _resource_state: [u32; 5],
    owned_allocation: u32,
    _tail: [u32; 2],
}

type OperationReleaseResources = unsafe extern "C" fn(*mut UiOperationPrefix);
type ElementReferenceRelease = unsafe extern "C" fn(*mut u8);
type ElementReferenceIsCurrent = unsafe extern "C" fn(*const u8) -> u32;
type Free = unsafe extern "C" fn(*mut u8);
type StringDestroy = unsafe extern "C" fn(*mut StringObject) -> *mut StringObject;
type ScopeDrop = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_operation_release_resources(_operation: *mut UiOperationPrefix) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_element_reference_release(_reference: *mut u8) {}

#[cfg(not(target_os = "none"))]
static mut OPERATION_RELEASE_RESOURCES: OperationReleaseResources = missing_operation_release_resources;
#[cfg(not(target_os = "none"))]
static mut ELEMENT_REFERENCE_RELEASE: ElementReferenceRelease = missing_element_reference_release;
#[cfg(not(target_os = "none"))]
static mut ELEMENT_REFERENCE_IS_CURRENT: ElementReferenceIsCurrent = ui_element_reference_is_current;
#[cfg(not(target_os = "none"))]
static mut FREE: Free = free;
#[cfg(not(target_os = "none"))]
static mut STRING_DESTROY: StringDestroy = string_object_destroy;
#[cfg(not(target_os = "none"))]
static mut SCOPE_DROP: ScopeDrop = context_scope_drop;
#[cfg(target_os = "none")]
static SCOPE_DROP: ScopeDrop = context_scope_drop;

#[inline(always)]
unsafe fn release_resources(operation: *mut UiOperationPrefix) {
    #[cfg(target_os = "none")]
    {
        let release: OperationReleaseResources = core::mem::transmute(0x0816_eb70usize);
        release(operation);
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(OPERATION_RELEASE_RESOURCES))(operation);
    }
}

#[inline(always)]
unsafe fn release_element_reference(reference: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let release: ElementReferenceRelease = core::mem::transmute(0x0828_4044usize);
        release(reference);
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(ELEMENT_REFERENCE_RELEASE))(reference);
    }
}

#[inline(always)]
unsafe fn element_reference_is_current(reference: *const u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        ui_element_reference_is_current(reference)
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(ELEMENT_REFERENCE_IS_CURRENT))(reference)
    }
}

#[inline(always)]
unsafe fn release_allocation(allocation: *mut u8) {
    #[cfg(target_os = "none")]
    {
        free(allocation);
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(FREE))(allocation);
    }
}

#[inline(always)]
unsafe fn destroy_string(string: *mut StringObject) {
    #[cfg(target_os = "none")]
    {
        string_object_destroy(string);
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(STRING_DESTROY))(string);
    }
}

#[inline(always)]
unsafe fn drop_context_scope(scope: *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(SCOPE_DROP))(scope);
}

/// ui_operation_destroy — original: `FUN_0816f050` @ `0x0816f050` (68 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @ `0x0816f050..0x0816f094`:
/// it first runs the operation-specific resource cleanup at `0x0816eb70`,
/// then checks the embedded UI element reference at word 5. A nonzero current
/// result calls its unported virtual-release helper at `0x08284044`. It frees
/// the nullable owned allocation at word 14, destroys the trailing string at
/// word 17, drops the embedded context scope at word 5, and returns `this`.
///
/// Verified call-site count: decoding every ARM `B`/`BL` word in `osos.dec`
/// finds 7 direct callers, all unconditional `bl` instructions: `0x0812cd84`,
/// `0x0812ce48`, `0x0819c320`, `0x0819c348`, `0x0819c488`, `0x081b6170`, and
/// `0x081b6288`. There are no direct non-link branches to this entry.
///
/// Deliberate host deviation: the two unported callees (`0x0816eb70` and
/// `0x08284044`) use replaceable no-op host boundaries. The existing Rust
/// ports are called directly on ARM; host tests replace their boundaries to
/// assert this destructor's observable ordering without depending on target
/// pointer-sized layouts.
///
/// # Safety
///
/// `operation` must name a readable prefix through word 16 and a valid
/// `StringObject` at word 17. Its resource cleanup may require further fields.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_operation_destroy")]
#[inline(never)]
pub unsafe extern "C" fn ui_operation_destroy(operation: *mut UiOperationPrefix) -> *mut UiOperationPrefix {
    release_resources(operation);

    let reference = core::ptr::addr_of_mut!((*operation).element_reference).cast::<u8>();
    if element_reference_is_current(reference) != 0 {
        release_element_reference(reference);
    }

    let allocation = (*operation).owned_allocation as usize as *mut u8;
    if !allocation.is_null() {
        release_allocation(allocation);
    }

    let string = operation.cast::<u32>().add(STRING_OBJECT_WORD_INDEX).cast::<StringObject>();
    destroy_string(string);
    drop_context_scope(reference);
    operation
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{LazyLock, Mutex};

    const RESOURCES: u8 = 1;
    const CURRENT: u8 = 2;
    const RELEASE_REFERENCE: u8 = 3;
    const FREE_ALLOCATION: u8 = 4;
    const DESTROY_STRING: u8 = 5;
    const DROP_SCOPE: u8 = 6;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 6] = [0; 6];
    static mut EVENT_COUNT: usize = 0;
    static mut CURRENT_RESULT: u32 = 0;
    static mut EXPECTED_OPERATION: *mut UiOperationPrefix = core::ptr::null_mut();
    static mut EXPECTED_REFERENCE: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_ALLOCATION: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_STRING: *mut StringObject = core::ptr::null_mut();

    unsafe fn record(event: u8) {
        EVENTS[EVENT_COUNT] = event;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn release_resources_stub(operation: *mut UiOperationPrefix) {
        assert_eq!(operation, EXPECTED_OPERATION);
        record(RESOURCES);
    }

    unsafe extern "C" fn is_current_stub(reference: *const u8) -> u32 {
        assert_eq!(reference.cast_mut(), EXPECTED_REFERENCE);
        record(CURRENT);
        CURRENT_RESULT
    }

    unsafe extern "C" fn release_reference_stub(reference: *mut u8) {
        assert_eq!(reference, EXPECTED_REFERENCE);
        record(RELEASE_REFERENCE);
    }

    unsafe extern "C" fn free_stub(allocation: *mut u8) {
        assert_eq!(allocation, EXPECTED_ALLOCATION);
        record(FREE_ALLOCATION);
    }

    unsafe extern "C" fn destroy_string_stub(string: *mut StringObject) -> *mut StringObject {
        assert_eq!(string, EXPECTED_STRING);
        record(DESTROY_STRING);
        string
    }

    unsafe extern "C" fn drop_scope_stub(scope: *mut u8) -> *mut u8 {
        assert_eq!(scope, EXPECTED_REFERENCE);
        record(DROP_SCOPE);
        scope
    }

    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::UI_OPERATION_DESTROY, 0x1000)
                .map(|slab| slab as usize)
        });
        SLAB.map(|slab| slab as *mut u8)
    }

    unsafe fn prepare(current_result: u32) -> *mut UiOperationPrefix {
        let slab = try_slab().expect("fixture slab checked by the caller's skip guard");
        let operation = slab.add(4).cast::<UiOperationPrefix>();
        let reference = core::ptr::addr_of_mut!((*operation).element_reference).cast::<u8>();
        let allocation = slab.add(0x300);
        let string = operation.cast::<u32>().add(STRING_OBJECT_WORD_INDEX).cast::<StringObject>();

        (*operation).owned_allocation = allocation as u32;
        EVENTS = [0; 6];
        EVENT_COUNT = 0;
        CURRENT_RESULT = current_result;
        EXPECTED_OPERATION = operation;
        EXPECTED_REFERENCE = reference;
        EXPECTED_ALLOCATION = allocation;
        EXPECTED_STRING = string;
        OPERATION_RELEASE_RESOURCES = release_resources_stub;
        ELEMENT_REFERENCE_IS_CURRENT = is_current_stub;
        ELEMENT_REFERENCE_RELEASE = release_reference_stub;
        FREE = free_stub;
        STRING_DESTROY = destroy_string_stub;
        SCOPE_DROP = drop_scope_stub;
        operation
    }

    #[test]
    fn stale_reference_skips_release_and_still_destroys_every_owned_member() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::operation_destroy");
            return;
        }

        unsafe {
            let operation = prepare(0);

            assert_eq!(ui_operation_destroy(operation), operation);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[RESOURCES, CURRENT, FREE_ALLOCATION, DESTROY_STRING, DROP_SCOPE]);
        }
    }

    #[test]
    fn any_nonzero_current_result_releases_the_reference_before_owned_members() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if try_slab().is_none() {
            crate::testing::note_missing_u32_fixture("ui::operation_destroy");
            return;
        }

        unsafe {
            let operation = prepare(7);

            assert_eq!(ui_operation_destroy(operation), operation);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[RESOURCES, CURRENT, RELEASE_REFERENCE, FREE_ALLOCATION, DESTROY_STRING, DROP_SCOPE]);
        }
    }
}

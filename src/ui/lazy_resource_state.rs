//! Lazy UI resource state singleton.
//!
//! The state belongs to the UI resource lifecycle. Its 0x18-byte allocation is
//! initialized by the still-unported local constructor at 0x081f5064.

use crate::heap::veneers::operator_new;

const UI_RESOURCE_STATE_SIZE: usize = 0x18;

/// Cached state pointer, originally the word addressed by the literal pool at
/// 0x081f5060 (0x089cfd24).
pub static mut UI_RESOURCE_STATE_CACHE: *mut u8 = core::ptr::null_mut();

type UiResourceStateConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_ui_resource_state_construct(state: *mut u8) -> *mut u8 {
    let construct: UiResourceStateConstruct = unsafe { core::mem::transmute(0x081f_5064usize) };
    unsafe { construct(state) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ui_resource_state_construct(_state: *mut u8) -> *mut u8 {
    panic!("lazy_ui_resource_state requires constructor 0x081f5064")
}

#[cfg(target_os = "none")]
static mut UI_RESOURCE_STATE_CONSTRUCT: UiResourceStateConstruct = retail_ui_resource_state_construct;
#[cfg(not(target_os = "none"))]
static mut UI_RESOURCE_STATE_CONSTRUCT: UiResourceStateConstruct = missing_ui_resource_state_construct;

#[inline(always)]
unsafe fn ui_resource_state_construct() -> UiResourceStateConstruct {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(UI_RESOURCE_STATE_CONSTRUCT)) }
}

/// lazy_ui_resource_state — original: `FUN_081f5034` @ 0x081f5034 (44 bytes).
/// The next real function starts at 0x081f5064. Raw words establish 3 inbound
/// plain `bl` call sites and 0 predicated call sites; its body has two plain
/// `bl` instructions, to `operator_new` @ 0x082aadd4 and the local constructor
/// @ 0x081f5064.
///
/// Returns the cached 0x18-byte UI resource state. A NULL cache allocates 24
/// bytes, passes the allocation to its constructor, caches that return value,
/// then reloads the cache. There is deliberately no NULL guard between
/// allocation and construction.
///
/// Deliberate deviation: the unported constructor remains a fixed retailOS
/// call on-device and a volatile host seam. Its identity is not inferred from
/// the single observed vtable-word store.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_ui_resource_state() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(UI_RESOURCE_STATE_CACHE);
    if unsafe { cache.read_volatile() }.is_null() {
        let allocated = unsafe { operator_new(UI_RESOURCE_STATE_SIZE) };
        let constructed = unsafe { ui_resource_state_construct()(allocated) };
        unsafe { cache.write_volatile(constructed) };
    }
    unsafe { cache.read_volatile() }
}

#[cfg(test)]
pub(crate) static UI_RESOURCE_STATE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::MutexGuard;

    static mut CONSTRUCT_CALLS: usize = 0;
    static mut CONSTRUCT_INPUT: *mut u8 = core::ptr::null_mut();
    static mut CONSTRUCT_RETURN: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_construct(state: *mut u8) -> *mut u8 {
        unsafe {
            CONSTRUCT_CALLS += 1;
            CONSTRUCT_INPUT = state;
            CONSTRUCT_RETURN
        }
    }

    fn install(construct_return: *mut u8) -> (MutexGuard<'static, ()>, UiResourceStateConstruct, *mut u8) {
        let lock = UI_RESOURCE_STATE_TEST_LOCK.lock();
        let previous_construct = unsafe { UI_RESOURCE_STATE_CONSTRUCT };
        let previous_cache = unsafe { UI_RESOURCE_STATE_CACHE };
        unsafe {
            CONSTRUCT_CALLS = 0;
            CONSTRUCT_INPUT = core::ptr::null_mut();
            CONSTRUCT_RETURN = construct_return;
            UI_RESOURCE_STATE_CACHE = core::ptr::null_mut();
            UI_RESOURCE_STATE_CONSTRUCT = recording_construct;
        }
        (lock, previous_construct, previous_cache)
    }

    fn restore(previous_construct: UiResourceStateConstruct, previous_cache: *mut u8) {
        unsafe {
            UI_RESOURCE_STATE_CONSTRUCT = previous_construct;
            UI_RESOURCE_STATE_CACHE = previous_cache;
        }
    }

    #[test]
    fn allocates_constructs_and_caches_constructor_result() {
        let heap_guard = crate::heap::veneers::tests::mock_heap();
        let allocated = crate::heap::veneers::tests::mock_block();
        let mut constructed = [0u8; UI_RESOURCE_STATE_SIZE];
        let (lock, previous_construct, previous_cache) = install(constructed.as_mut_ptr());
        unsafe { crate::heap::veneers::tests::set_alloc_ret(allocated) };

        assert_eq!(unsafe { lazy_ui_resource_state() }, constructed.as_mut_ptr());
        assert_eq!(unsafe { lazy_ui_resource_state() }, constructed.as_mut_ptr());
        assert_eq!(unsafe { CONSTRUCT_CALLS }, 1);
        assert_eq!(unsafe { CONSTRUCT_INPUT }, allocated);
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, UI_RESOURCE_STATE_SIZE, 2));

        restore(previous_construct, previous_cache);
        drop(lock);
        drop(heap_guard);
    }

    #[test]
    fn forwards_null_allocation_to_constructor() {
        let heap_guard = crate::heap::veneers::tests::mock_heap();
        let mut constructed = [0u8; UI_RESOURCE_STATE_SIZE];
        let (lock, previous_construct, previous_cache) = install(constructed.as_mut_ptr());
        unsafe { crate::heap::veneers::tests::set_alloc_ret(core::ptr::null_mut()) };

        assert_eq!(unsafe { lazy_ui_resource_state() }, constructed.as_mut_ptr());
        assert_eq!(unsafe { CONSTRUCT_CALLS }, 1);
        assert!(unsafe { CONSTRUCT_INPUT }.is_null());
        assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, UI_RESOURCE_STATE_SIZE, 2));

        restore(previous_construct, previous_cache);
        drop(lock);
        drop(heap_guard);
    }
}

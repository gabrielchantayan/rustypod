//! `adjusted_subobject_initializer` — retailOS `FUN_083e78f8` @
//! **0x083e78f8** (136 bytes, `0x083e78f8..0x083e797f`; the next separately
//! linked function begins at `0x083e798c`, after this function's three literal
//! words at `0x083e7980..0x083e7988`). Raw A32 decoding finds two inbound plain
//! `bl` calls (0x082a7be4 and 0x082a91b8), no predicated inbound `bl` calls,
//! and three outbound plain `bl` calls (0x082a8b50, 0x082a7280, 0x082a8ba0).
//! The handler invocation between the second and third calls is an indirect
//! `mov pc, r2` through handler.vtable slot +0x30, not a direct call.
//!
//! # Algorithm
//!
//! Initialize fixed state words in the adjusted subobject, retain-copy its
//! shared registry handle, select a handler for type ID 0x08a0fba0, invoke the
//! handler's slot +0x30 with selector 0x20, release the temporary handle, and
//! store the handler's low result halfword at +0x3c. Deliberate deviations:
//! the two unported shared-handle operations and unrecovered virtual slot use
//! fixed retail addresses on target builds and replaceable host seams.

use crate::app::typed_handler_registry_lookup::typed_handler_registry_lookup;


#[inline(always)]
fn handler_type_id() -> *const u32 {
    #[cfg(target_os = "none")]
    {
        HANDLER_TYPE_ID_ADDRESS as *const u32
    }
    #[cfg(not(target_os = "none"))]
    {
        static TYPE_ID: [u32; 4] = [0x42f6_df58, 0x6cd7_0935, 0x9ff4_111c, 0x8160_f11f];
        TYPE_ID.as_ptr()
    }
}
const RETAIL_SHARED_HANDLE_RETAIN_COPY: usize = 0x082a_8b50;
const RETAIL_SHARED_HANDLE_RELEASE: usize = 0x082a_8ba0;
const HANDLER_TYPE_ID_ADDRESS: usize = 0x08a0_fba0;
const DEFAULT_HANDLER_ENTRY: usize = 0x083a_b3c4;

type SharedHandleRetainCopy = unsafe extern "C" fn(*mut u8, *mut u8);
type SharedHandleRelease = unsafe extern "C" fn(*mut u8);
type HandlerSlot30 = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shared_handle_retain_copy(destination: *mut u8, source: *mut u8) {
    let retain: SharedHandleRetainCopy = unsafe { core::mem::transmute(RETAIL_SHARED_HANDLE_RETAIN_COPY) };
    unsafe { retain(destination, source) };
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn shared_handle_release(handle: *mut u8) {
    let release: SharedHandleRelease = unsafe { core::mem::transmute(RETAIL_SHARED_HANDLE_RELEASE) };
    unsafe { release(handle) };
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn handler_slot_30(handler: *mut u8, selector: u32) -> u32 {
    let vtable = unsafe { (handler as *const u32).read() };
    let slot_address = unsafe { ((vtable as usize + 0x30) as *const u32).read() };
    let slot: HandlerSlot30 = unsafe { core::mem::transmute(slot_address as usize) };
    unsafe { slot(handler, selector) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_shared_handle_retain_copy(_: *mut u8, _: *mut u8) {
    panic!("install adjusted-subobject shared-handle retain host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_shared_handle_release(_: *mut u8) {
    panic!("install adjusted-subobject shared-handle release host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handler_slot_30(_: *mut u8, _: u32) -> u32 {
    panic!("install adjusted-subobject handler slot host seam")
}

/// Host boundaries for the still-retail shared-handle and virtual operations.
#[cfg(not(target_os = "none"))]
pub static mut ADJUSTED_SUBOBJECT_SHARED_HANDLE_RETAIN_COPY: SharedHandleRetainCopy = missing_shared_handle_retain_copy;
#[cfg(not(target_os = "none"))]
pub static mut ADJUSTED_SUBOBJECT_SHARED_HANDLE_RELEASE: SharedHandleRelease = missing_shared_handle_release;
#[cfg(not(target_os = "none"))]
pub static mut ADJUSTED_SUBOBJECT_HANDLER_SLOT_30: HandlerSlot30 = missing_handler_slot_30;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shared_handle_retain_copy(destination: *mut u8, source: *mut u8) {
    let retain = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ADJUSTED_SUBOBJECT_SHARED_HANDLE_RETAIN_COPY)) };
    unsafe { retain(destination, source) };
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn shared_handle_release(handle: *mut u8) {
    let release = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ADJUSTED_SUBOBJECT_SHARED_HANDLE_RELEASE)) };
    unsafe { release(handle) };
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn handler_slot_30(handler: *mut u8, selector: u32) -> u32 {
    let call = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ADJUSTED_SUBOBJECT_HANDLER_SLOT_30)) };
    unsafe { call(handler, selector) }
}

/// Initializes the adjusted registry-owning subobject.
///
/// # Safety
///
/// `subobject` must identify at least 64 writable bytes; its +0x18 shared
/// handle must satisfy the retail shared-handle retain/release contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn adjusted_subobject_initializer(subobject: *mut u8, initialization_flag: u32) {
    unsafe {
        subobject.add(0x34).cast::<u32>().write(initialization_flag);
        subobject.add(0x38).cast::<u32>().write(0);
        subobject.add(0x10).cast::<u32>().write((initialization_flag == 0) as u32);
        subobject.add(0x14).cast::<u32>().write(0);
        subobject.add(0x0c).cast::<u32>().write(0);
        subobject.add(0x08).cast::<u32>().write(6);
        subobject.add(0x04).cast::<u32>().write(0x1002);

        let mut temporary_handle = [0usize; 1];
        shared_handle_retain_copy(temporary_handle.as_mut_ptr().cast(), subobject.add(0x18));
        let handler = typed_handler_registry_lookup(
            temporary_handle.as_mut_ptr().cast(),
            handler_type_id(),
            1,
            0x20,
            DEFAULT_HANDLER_ENTRY,
        );
        let result = handler_slot_30(handler, 0x20);
        shared_handle_release(temporary_handle.as_mut_ptr().cast());
        subobject.add(0x3c).cast::<u16>().write(result as u16);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::typed_handler_registry_lookup::{TypedHandlerRegistryLookup, TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK, TYPED_HANDLER_REGISTRY_SLOW_LOOKUP};
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RETAIN_SOURCE: *mut u8 = core::ptr::null_mut();
    static mut RELEASE_HANDLE: *mut u8 = core::ptr::null_mut();
    static mut LOOKUP_TYPE_ID: *const u32 = core::ptr::null();
    static mut LOOKUP_DIRECTION: u32 = 0;
    static mut LOOKUP_FLAGS: u32 = 0;
    static mut LOOKUP_DEFAULT: usize = 0;
    static mut SLOT_HANDLER: *mut u8 = core::ptr::null_mut();
    static mut SLOT_SELECTOR: u32 = 0;
    static mut HANDLER: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn retain(destination: *mut u8, source: *mut u8) {
        unsafe {
            addr_of_mut!(RETAIN_SOURCE).write(source);
            destination.cast::<*mut u8>().write(source.cast::<*mut u8>().read());
        };
    }
    unsafe extern "C" fn release(handle: *mut u8) {
        unsafe {
            addr_of_mut!(RELEASE_HANDLE).write(handle);
            assert_ne!(handle.cast::<*mut u8>().read(), core::ptr::null_mut());
        };
    }
    unsafe extern "C" fn slow_lookup(_: *mut *mut u8, type_id: *const u32, direction: u32, flags: u32, default_entry: usize) -> *mut u8 {
        unsafe {
            addr_of_mut!(LOOKUP_TYPE_ID).write(type_id);
            addr_of_mut!(LOOKUP_DIRECTION).write(direction);
            addr_of_mut!(LOOKUP_FLAGS).write(flags);
            addr_of_mut!(LOOKUP_DEFAULT).write(default_entry);
            HANDLER
        }
    }
    unsafe extern "C" fn slot_30(handler: *mut u8, selector: u32) -> u32 {
        unsafe { addr_of_mut!(SLOT_HANDLER).write(handler); addr_of_mut!(SLOT_SELECTOR).write(selector) };
        0x1234_abcd
    }

    #[test]
    fn initializes_state_selects_handler_and_releases_temporary_handle() {
        let _lock = LOCK.lock();
        let _lookup_lock = TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK.lock().unwrap();
        let mut subobject = [0xa5u8; 64];
        let mut registry = [0u32; 4];
        let mut handler = 0u8;
        unsafe {
            addr_of_mut!(HANDLER).write((&mut handler) as *mut u8);
            addr_of_mut!(ADJUSTED_SUBOBJECT_SHARED_HANDLE_RETAIN_COPY).write(retain);
            addr_of_mut!(ADJUSTED_SUBOBJECT_SHARED_HANDLE_RELEASE).write(release);
            addr_of_mut!(ADJUSTED_SUBOBJECT_HANDLER_SLOT_30).write(slot_30);
            addr_of_mut!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP).write(slow_lookup as TypedHandlerRegistryLookup);
            (subobject.as_mut_ptr().add(0x18) as *mut *mut u8).write(registry.as_mut_ptr().cast());
            adjusted_subobject_initializer(subobject.as_mut_ptr(), 0);
            assert_eq!(subobject.as_ptr().add(4).cast::<u32>().read(), 0x1002);
            assert_eq!(subobject.as_ptr().add(8).cast::<u32>().read(), 6);
            assert_eq!(subobject.as_ptr().add(0x0c).cast::<u32>().read(), 0);
            assert_eq!(subobject.as_ptr().add(0x10).cast::<u32>().read(), 1);
            assert_eq!(subobject.as_ptr().add(0x14).cast::<u32>().read(), 0);
            assert_eq!(subobject.as_ptr().add(0x34).cast::<u32>().read(), 0);
            assert_eq!(subobject.as_ptr().add(0x38).cast::<u32>().read(), 0);
            assert_eq!(subobject.as_ptr().add(0x3c).cast::<u16>().read(), 0xabcd);
            assert_eq!(addr_of!(RETAIN_SOURCE).read(), subobject.as_mut_ptr().add(0x18));
            assert_eq!(addr_of!(LOOKUP_TYPE_ID).read(), handler_type_id());
            assert_eq!(addr_of!(LOOKUP_DIRECTION).read(), 1);
            assert_eq!(addr_of!(LOOKUP_FLAGS).read(), 0x20);
            assert_eq!(addr_of!(LOOKUP_DEFAULT).read(), DEFAULT_HANDLER_ENTRY);
            assert_eq!(addr_of!(SLOT_HANDLER).read(), (&mut handler) as *mut u8);
            assert_eq!(addr_of!(SLOT_SELECTOR).read(), 0x20);
            assert_ne!(addr_of!(RELEASE_HANDLE).read(), core::ptr::null_mut());
        }
    }

    #[test]
    fn only_zero_initialization_flag_sets_the_boolean_state_word() {
        let _lock = LOCK.lock();
        let _lookup_lock = TYPED_HANDLER_REGISTRY_LOOKUP_TEST_LOCK.lock().unwrap();
        let mut subobject = [0u8; 64];
        let mut registry = [0u32; 4];
        let mut handler = 0u8;
        unsafe {
            addr_of_mut!(HANDLER).write((&mut handler) as *mut u8);
            addr_of_mut!(ADJUSTED_SUBOBJECT_SHARED_HANDLE_RETAIN_COPY).write(retain);
            addr_of_mut!(ADJUSTED_SUBOBJECT_SHARED_HANDLE_RELEASE).write(release);
            addr_of_mut!(ADJUSTED_SUBOBJECT_HANDLER_SLOT_30).write(slot_30);
            addr_of_mut!(TYPED_HANDLER_REGISTRY_SLOW_LOOKUP).write(slow_lookup as TypedHandlerRegistryLookup);
            (subobject.as_mut_ptr().add(0x18) as *mut *mut u8).write(registry.as_mut_ptr().cast());
            adjusted_subobject_initializer(subobject.as_mut_ptr(), 2);
            assert_eq!(subobject.as_ptr().add(0x10).cast::<u32>().read(), 0);
            assert_eq!(subobject.as_ptr().add(0x34).cast::<u32>().read(), 2);
        }
    }
}

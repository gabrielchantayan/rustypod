//! Builds a keyed message buffer and optionally constructs its owning object.
//!
//! `message_builder_allocate_and_construct` — retailOS `FUN_082caec0` at
//! `0x082caec0` (**144 bytes, `0x082caec0..0x082caf50`**). Raw `osos.dec`
//! words end at the final `pop {r4,r5,pc}` at `0x082caf4c`; the five literal
//! words begin at `0x082caf50`, and the next real function begins at
//! `0x082caf64`. Raw A32 decoding finds four plain outbound `bl` instructions
//! and two predicated `blne` instructions. Full-image decoding finds two
//! inbound plain `bl` instructions and no predicated inbound calls.
//!
//! # Algorithm
//!
//! Initializes a 104-byte stack message builder with the supplied key, appends
//! mandatory selector `0x3033` with value four, and, when configuration is
//! present, appends selectors `0x3057` and `0x3056` for its two halfword
//! fields. It then allocates 168 bytes and gives the allocation, builder, and
//! configuration's first word to the final object constructor. Without a
//! configuration it stores the retail default value at `0x089ca320` and
//! returns zero.
//!
//! # Deliberate deviations
//!
//! The three unported callees have no recovered semantic identities beyond
//! their verified ABIs. Target builds call their retailOS addresses; host
//! builds use narrow seams. The host default-word replaces the live target
//! global.

const MESSAGE_BUILDER_SIZE: usize = 104;
const REQUIRED_SELECTOR: u32 = 0x3033;
const FIRST_OPTIONAL_SELECTOR: u32 = 0x3057;
const SECOND_OPTIONAL_SELECTOR: u32 = 0x3056;
const DEFAULT_VALUE: u32 = 0x300b;
const DEFAULT_GLOBAL: usize = 0x089c_a320;
const OBJECT_SIZE: usize = 0xa8;

pub type MessageBuilderInitialize = unsafe extern "C" fn(*mut u8, u32, u32, u32);
pub type MessageBuilderAppend = unsafe extern "C" fn(*mut u8, u32, u32);
pub type MessageObjectConstruct = unsafe extern "C" fn(*mut u8, *mut u8, u32) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_builder_initialize(_: *mut u8, _: u32, _: u32, _: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_builder_append(_: *mut u8, _: u32, _: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_construct(_: *mut u8, _: *mut u8, _: u32) -> *mut u8 { core::ptr::null_mut() }

#[cfg(not(target_os = "none"))]
pub static mut MESSAGE_BUILDER_INITIALIZE: MessageBuilderInitialize = missing_builder_initialize;
#[cfg(not(target_os = "none"))]
pub static mut MESSAGE_BUILDER_APPEND: MessageBuilderAppend = missing_builder_append;
#[cfg(not(target_os = "none"))]
pub static mut MESSAGE_OBJECT_CONSTRUCT: MessageObjectConstruct = missing_object_construct;
#[cfg(not(target_os = "none"))]
static mut HOST_DEFAULT_VALUE: u32 = 0;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn builder_initialize_target() -> MessageBuilderInitialize { core::mem::transmute(0x0824_cb64usize) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn builder_append_target() -> MessageBuilderAppend { core::mem::transmute(0x0824_c8f8usize) }
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn object_construct_target() -> MessageObjectConstruct { core::mem::transmute(0x0825_6938usize) }

/// Builds the message and constructs its object when `configuration` is non-null.
///
/// # Safety
/// `configuration`, when non-null, must be four-byte aligned and point to at
/// least eight readable bytes. The target callees receive a valid 104-byte
/// builder and preserve their retail ABIs; allocation and construction remain
/// unguarded exactly as in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_builder_allocate_and_construct(
    _unused: u32,
    key: u32,
    configuration: *const u8,
) -> *mut u8 {
    let mut builder_storage = core::mem::MaybeUninit::<[u8; MESSAGE_BUILDER_SIZE]>::uninit();
    let builder = builder_storage.as_mut_ptr().cast::<u8>();
    #[cfg(target_os = "none")]
    unsafe {
        builder_initialize_target()(builder, key, 0, 0);
        builder_append_target()(builder, REQUIRED_SELECTOR, 4);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        MESSAGE_BUILDER_INITIALIZE(builder, key, 0, 0);
        MESSAGE_BUILDER_APPEND(builder, REQUIRED_SELECTOR, 4);
    }

    if configuration.is_null() {
        #[cfg(target_os = "none")]
        unsafe { (DEFAULT_GLOBAL as *mut u32).write_volatile(DEFAULT_VALUE) };
        #[cfg(not(target_os = "none"))]
        unsafe { HOST_DEFAULT_VALUE = DEFAULT_VALUE };
        return core::ptr::null_mut();
    }

    unsafe {
        if configuration.add(4).cast::<u16>().read() != 0 {
            #[cfg(target_os = "none")]
            builder_append_target()(builder, FIRST_OPTIONAL_SELECTOR, 0);
            #[cfg(not(target_os = "none"))]
            MESSAGE_BUILDER_APPEND(builder, FIRST_OPTIONAL_SELECTOR, 0);
        }
        if configuration.add(6).cast::<u16>().read() != 0 {
            #[cfg(target_os = "none")]
            builder_append_target()(builder, SECOND_OPTIONAL_SELECTOR, 0);
            #[cfg(not(target_os = "none"))]
            MESSAGE_BUILDER_APPEND(builder, SECOND_OPTIONAL_SELECTOR, 0);
        }
        let object = crate::heap::veneers::operator_new(OBJECT_SIZE);
        let first_word = configuration.cast::<u32>().read();
        #[cfg(target_os = "none")]
        return object_construct_target()(object, builder, first_word);
        #[cfg(not(target_os = "none"))]
        return MESSAGE_OBJECT_CONSTRUCT(object, builder, first_word);
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut STORAGE: [u8; OBJECT_SIZE] = [0; OBJECT_SIZE];
    static mut EVENTS: [(u32, u32); 4] = [(0, 0); 4];
    static mut EVENT_COUNT: usize = 0;
    static mut CONSTRUCT_WORD: u32 = 0;

    unsafe extern "C" fn allocate(_: *mut HeapDescriptorDescriptor, size: usize, tag: usize) -> *mut u8 {
        assert_eq!((size, tag), (OBJECT_SIZE, 2)); ptr::addr_of_mut!(STORAGE).cast()
    }
    unsafe extern "C" fn create(desc: *mut HeapDescriptor, _: *mut u8, _: usize) -> *mut HeapDescriptorDescriptor { desc.cast() }
    unsafe extern "C" fn no_alloc(_: *mut HeapDescriptorDescriptor, _: usize, _: usize) -> *mut u8 { ptr::null_mut() }
    unsafe extern "C" fn no_free(_: *mut HeapDescriptorDescriptor, _: *mut u8, _: usize) {}
    unsafe extern "C" fn no_realloc(_: *mut HeapDescriptorDescriptor, _: *mut u8, _: usize, _: usize, _: usize) -> *mut u8 { ptr::null_mut() }
    unsafe extern "C" fn no_handler(_: usize) {}
    unsafe extern "C" fn no_raise(_: i32, _: i32) -> i32 { 0 }
    unsafe extern "C" fn no_exit() {}
    unsafe extern "C" fn no_terminate(_: i32) {}
    unsafe extern "C" fn initialize(_: *mut u8, _: u32, _: u32, _: u32) {}
    unsafe extern "C" fn append(_: *mut u8, selector: u32, value: u32) {
        unsafe { EVENTS[EVENT_COUNT] = (selector, value); EVENT_COUNT += 1 }
    }
    unsafe extern "C" fn construct(object: *mut u8, _: *mut u8, word: u32) -> *mut u8 {
        unsafe { CONSTRUCT_WORD = word; object }
    }

    struct Restore { heap: HeapVeneerOps, initialize: MessageBuilderInitialize, append: MessageBuilderAppend, construct: MessageObjectConstruct, default: u32 }
    impl Drop for Restore { fn drop(&mut self) { unsafe {
        HEAP_OPS = self.heap; MESSAGE_BUILDER_INITIALIZE = self.initialize; MESSAGE_BUILDER_APPEND = self.append;
        MESSAGE_OBJECT_CONSTRUCT = self.construct; HOST_DEFAULT_VALUE = self.default;
    } } }
    fn install() -> Restore { unsafe {
        let restore = Restore { heap: HEAP_OPS, initialize: MESSAGE_BUILDER_INITIALIZE, append: MESSAGE_BUILDER_APPEND, construct: MESSAGE_OBJECT_CONSTRUCT, default: HOST_DEFAULT_VALUE };
        HEAP_OPS = HeapVeneerOps { alloc: allocate, alloc_zero: no_alloc, free: no_free, realloc: no_realloc, create, new_handler: no_handler, raise: no_raise, exit: no_exit, terminate: no_terminate };
        MESSAGE_BUILDER_INITIALIZE = initialize; MESSAGE_BUILDER_APPEND = append; MESSAGE_OBJECT_CONSTRUCT = construct;
        EVENT_COUNT = 0; EVENTS = [(0, 0); 4]; CONSTRUCT_WORD = 0; HOST_DEFAULT_VALUE = 0; restore
    } }

    #[test]
    fn null_configuration_sets_default_after_required_message_entry() {
        let _lock = LOCK.lock(); let _restore = install();
        assert!(unsafe { message_builder_allocate_and_construct(0, 7, ptr::null()) }.is_null());
        unsafe { assert_eq!(HOST_DEFAULT_VALUE, DEFAULT_VALUE); assert_eq!(&EVENTS[..EVENT_COUNT], &[(REQUIRED_SELECTOR, 4)]) };
    }

    #[test]
    fn configuration_appends_nonzero_fields_and_constructs_from_first_word() {
        let _lock = LOCK.lock(); let _restore = install();
        let configuration = [0x78, 0x56, 0x34, 0x12, 1, 0, 2, 0];
        let object = unsafe { message_builder_allocate_and_construct(0, 7, configuration.as_ptr()) };
        assert_eq!(object, unsafe { ptr::addr_of_mut!(STORAGE).cast() });
        unsafe {
            assert_eq!(CONSTRUCT_WORD, 0x1234_5678);
            assert_eq!(&EVENTS[..EVENT_COUNT], &[(REQUIRED_SELECTOR, 4), (FIRST_OPTIONAL_SELECTOR, 0), (SECOND_OPTIONAL_SELECTOR, 0)]);
        }
    }
}

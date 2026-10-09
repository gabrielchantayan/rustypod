//! Header-buffer factory — `FUN_080f6978` @ 0x080f6978.
//!
//! True size: 92 bytes, [0x080f6978, 0x080f69d4); the next PUSH begins
//! header_buffer_release. Raw words verify three plain BL, zero predicated
//! BL, and one predicated BLXEQ through vtable slot +4. Allocate an eight-byte
//! owner, construct it, then build a copied payload with a 12-byte header.
//! A NULL constructor result skips building. A zero builder result dispatches
//! the deleting destructor, but the original owner pointer is still returned
//! (potentially dangling); this port deliberately does not repair that behavior.
//!
//! Deviations: pointer fields and allocation size widen together on hosts.
//! The unported constructor @ 0x080f6a04 and builder @ 0x080f68f4 remain
//! resident ABI calls, with explicit host seams; operator_new uses its existing
//! Rust port. Conditional ARM execution becomes Rust branches.

use crate::heap::header_buffer_release::HeaderBuffer;

pub type HeaderBufferAllocate = unsafe extern "C" fn(usize) -> *mut u8;
pub type HeaderBufferConstruct = unsafe extern "C" fn(*mut HeaderBuffer) -> *mut HeaderBuffer;
pub type HeaderBufferBuild = unsafe extern "C" fn(*mut HeaderBuffer, *const u8, u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_construct(_: *mut HeaderBuffer) -> *mut HeaderBuffer {
    panic!("resident header-buffer constructor requires a host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_build(_: *mut HeaderBuffer, _: *const u8, _: u32, _: u32, _: u32) -> u32 {
    panic!("resident header-buffer builder requires a host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut HEADER_BUFFER_ALLOCATE: HeaderBufferAllocate = crate::heap::veneers::operator_new;
#[cfg(not(target_os = "none"))]
pub static mut HEADER_BUFFER_CONSTRUCT: HeaderBufferConstruct = unavailable_construct;
#[cfg(not(target_os = "none"))]
pub static mut HEADER_BUFFER_BUILD: HeaderBufferBuild = unavailable_build;

/// # Safety
/// Source must satisfy the resident builder's length/copy contract. The
/// constructor must accept the allocator result (the stock code has no NULL
/// allocation guard). A non-NULL constructed owner needs a valid vtable whose
/// second pointer is its deleting destructor. Host seams require exclusive setup.
/// The returned pointer must not be dereferenced when building failed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn header_buffer_create(source: *const u8, length: u32, selector: u32, context: u32) -> *mut HeaderBuffer {
    #[cfg(target_os = "none")]
    let (allocate, construct, build): (HeaderBufferAllocate, HeaderBufferConstruct, HeaderBufferBuild) = (
        crate::heap::veneers::operator_new,
        core::mem::transmute(0x080f_6a04usize),
        core::mem::transmute(0x080f_68f4usize),
    );
    #[cfg(not(target_os = "none"))]
    let (allocate, construct, build) = (HEADER_BUFFER_ALLOCATE, HEADER_BUFFER_CONSTRUCT, HEADER_BUFFER_BUILD);
    let owner = construct(allocate(core::mem::size_of::<HeaderBuffer>()).cast());
    if !owner.is_null() && build(owner, source, length, selector, context) == 0 {
        let slots = (*owner).vtable.cast::<unsafe extern "C" fn(*mut HeaderBuffer)>();
        let destroy = slots.add(1).read();
        destroy(owner);
    }
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<HeaderBuffer>());
        std::boxed::Box::into_raw(std::boxed::Box::new(HeaderBuffer {
            vtable: core::ptr::null(), allocation: core::ptr::null_mut(),
        })).cast()
    }
    unsafe extern "C" fn destroy(owner: *mut HeaderBuffer) {
        // Retain fixture storage so the returned identity can be checked safely.
        (*owner).allocation = core::ptr::null_mut();
    }
    unsafe extern "C" fn wrong_slot(_: *mut HeaderBuffer) { panic!("wrong vtable slot") }
    static VTABLE: [unsafe extern "C" fn(*mut HeaderBuffer); 2] = [wrong_slot, destroy];
    unsafe extern "C" fn construct(owner: *mut HeaderBuffer) -> *mut HeaderBuffer {
        (*owner).vtable = VTABLE.as_ptr().cast();
        owner
    }
    unsafe extern "C" fn build(owner: *mut HeaderBuffer, source: *const u8, length: u32, selector: u32, _: u32) -> u32 {
        // Real observable partial state makes cleanup vs success distinguishable.
        (*owner).allocation = source.cast_mut();
        if length == 0 { selector } else { 0 }
    }
    unsafe extern "C" fn null_construct(owner: *mut HeaderBuffer) -> *mut HeaderBuffer {
        drop(std::boxed::Box::from_raw(owner));
        core::ptr::null_mut()
    }
    unsafe extern "C" fn forbidden_build(_: *mut HeaderBuffer, _: *const u8, _: u32, _: u32, _: u32) -> u32 {
        panic!("NULL constructor result must skip builder")
    }

    struct Restore(HeaderBufferAllocate, HeaderBufferConstruct, HeaderBufferBuild);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            HEADER_BUFFER_ALLOCATE = self.0;
            HEADER_BUFFER_CONSTRUCT = self.1;
            HEADER_BUFFER_BUILD = self.2;
        } }
    }
    unsafe fn install(ctor: HeaderBufferConstruct, builder: HeaderBufferBuild) -> Restore {
        let restore = Restore(HEADER_BUFFER_ALLOCATE, HEADER_BUFFER_CONSTRUCT, HEADER_BUFFER_BUILD);
        HEADER_BUFFER_ALLOCATE = allocate;
        HEADER_BUFFER_CONSTRUCT = ctor;
        HEADER_BUFFER_BUILD = builder;
        restore
    }

    #[test]
    fn builder_failure_dispatches_second_slot_but_returns_owner() {
        let _lock = LOCK.lock();
        let _restore = unsafe { install(construct, build) };
        let source = [17u8];
        let owner = unsafe { header_buffer_create(source.as_ptr(), 1, 99, 0) };
        assert!(!owner.is_null());
        unsafe {
            assert!((*owner).allocation.is_null());
            assert_eq!((*owner).vtable, VTABLE.as_ptr().cast());
            drop(std::boxed::Box::from_raw(owner));
        }
    }

    #[test]
    fn any_nonzero_builder_result_keeps_owner_alive() {
        let _lock = LOCK.lock();
        let _restore = unsafe { install(construct, build) };
        let source = [17u8];
        for result in [1, 2, 0x8000_0000, u32::MAX] {
            let owner = unsafe { header_buffer_create(source.as_ptr(), 0, result, 0) };
            unsafe {
                assert_eq!((*owner).allocation, source.as_ptr().cast_mut());
                drop(std::boxed::Box::from_raw(owner));
            }
        }
    }

    #[test]
    fn null_constructor_result_skips_builder_and_vtable() {
        let _lock = LOCK.lock();
        let _restore = unsafe { install(null_construct, forbidden_build) };
        assert!(unsafe { header_buffer_create(core::ptr::null(), u32::MAX, 0, 0) }.is_null());
    }
}

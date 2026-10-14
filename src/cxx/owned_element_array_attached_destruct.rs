//! `owned_element_array_attached_destruct` — retailOS `FUN_083d1d00` @
//! `0x083d1d00`, **60 bytes** (56 code bytes plus vtable literal).
//!
//! Raw words establish the next function at `0x083d1d3c`. The body has one
//! plain BL to `owned_element_array_release`, zero predicated BLs, one BLXNE
//! through attached-object slot +0x1c, and a tail B to `observable_array_destruct`.
//! Whole-image decoding finds one incoming plain BL at `0x0826b718`, zero
//! predicated BL callers; its caller null-checks and then deletes the result.
//!
//! Install vtable 0x089a5568, release the optional attachment at +0x14, release
//! owned elements, then destroy the observable-array base and return `this`.
//! Deliberate deviations: ordinary Rust control flow replaces BLXNE/tail B;
//! host builds substitute the virtual call and owned-element cleanup because
//! that existing port uses a widened host layout. Firmware calls the ported
//! cleanup directly and dispatches the real target-width virtual slot.

#[cfg(target_os = "none")]
use super::owned_element_array_release::{owned_element_array_release, OwnedElementArrayRelease};
use super::observable_array::{observable_array_destruct, ObservableArray};

type ReleaseAttached = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
type ReleaseElements = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_attached(_: *mut u8) {
    panic!("install owned array attached destructor host virtual operation")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_elements(_: *mut u32) {
    panic!("install owned array attached destructor host element operation")
}
#[cfg(not(target_os = "none"))]
pub static mut OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE: ReleaseAttached = missing_attached;
#[cfg(not(target_os = "none"))]
pub static mut OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE_ELEMENTS: ReleaseElements = missing_elements;

/// # Safety
/// `this` must be a writable target-layout owned-element array of at least six
/// words, satisfying both cleanup callees' contracts. Its nonzero word +0x14
/// must identify an object with a callable release slot +0x1c. Host callers
/// must install operations for the target-width virtual and element calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_element_array_attached_destruct(this: *mut u32) -> *mut u32 {
    this.write_volatile(0x089a_5568);
    let attached = this.add(5).read_volatile() as usize as *mut u8;
    if !attached.is_null() {
        #[cfg(target_os = "none")]
        {
            let vtable = attached.cast::<u32>().read_volatile() as usize as *const u32;
            let release: ReleaseAttached = core::mem::transmute(vtable.add(7).read_volatile() as usize);
            release(attached);
        }
        #[cfg(not(target_os = "none"))]
        core::ptr::addr_of!(OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE).read_volatile()(attached);
    }
    #[cfg(target_os = "none")]
    owned_element_array_release(this.cast::<OwnedElementArrayRelease>());
    #[cfg(not(target_os = "none"))]
    core::ptr::addr_of!(OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE_ELEMENTS).read_volatile()(this);
    observable_array_destruct(this.cast::<ObservableArray>()).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CURRENT: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn release_attached(object: *mut u8) {
        assert_eq!(object as usize, 0x1234_5000);
        assert_eq!(CURRENT.read(), 0x089a_5568);
        assert_eq!(CURRENT.add(1).read(), 7);
        CURRENT.add(1).write(3);
        CURRENT.add(5).write(0);
    }

    unsafe extern "C" fn release_elements(this: *mut u32) {
        assert_eq!(this.read(), 0x089a_5568);
        assert_eq!(this.add(5).read(), 0);
        // The attached callback's mutation must precede element cleanup.
        assert_eq!(this.add(1).read(), 3);
        this.add(1).write(1);
    }

    #[test]
    fn attachment_release_precedes_cleanup_and_base_reset() {
        let _lock = LOCK.lock();
        unsafe {
            let old_attached = OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE;
            let old_elements = OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE_ELEMENTS;
            OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE = release_attached;
            OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE_ELEMENTS = release_elements;
            for attached in [0, 0x1234_5000] {
                let mut object = [0, if attached == 0 { 3 } else { 7 }, 0, 0, 0, attached];
                CURRENT = object.as_mut_ptr();
                let result = owned_element_array_attached_destruct(CURRENT);
                assert_eq!(result, CURRENT);
                assert_eq!(object, [super::super::observable_array::OBSERVABLE_ARRAY_VTABLE, 0, 0, 0, 0, 0]);
            }
            CURRENT = core::ptr::null_mut();
            OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE = old_attached;
            OWNED_ELEMENT_ARRAY_ATTACHED_RELEASE_ELEMENTS = old_elements;
        }
    }
}

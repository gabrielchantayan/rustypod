//! Screen resource-selector construction at `0x0815a47c` (FUN_0815a47c).
//! True extent: 80 instruction bytes plus 8 literal bytes, ending at the next
//! function, `0x0815a4d4`. Verified outgoing calls: 2 plain BL, 0 predicated BL;
//! whole-image decoding finds 2 inbound plain BL, 0 predicated BL.
//! Calls the cursor-bearing screen base constructor with storage and provider,
//! installs vtable 0x08987548, clears bytes +0x24/+0x30 and word +0x2c,
//! installs default state 0x089a6044 at +0x28, then stores the class-6 checked
//! provider at +0x1c and owner at +0x20. Operates on the base call's result.
//! Deliberate deviations: host builds substitute only the unported base call;
//! object storage remains target-width words, including pointer-valued fields.
//! No extra NULL guards, padding writes, allocation, or inferred class name.

use core::ptr::write_volatile;
use crate::app::registry::{object_cast_to_class, FrameworkObject};

type ScreenCursorBaseConstruct = unsafe extern "C" fn(*mut u32, *mut FrameworkObject) -> *mut u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_base(_: *mut u32, _: *mut FrameworkObject) -> *mut u32 {
    panic!("host must install screen cursor base constructor")
}
#[cfg(not(target_os = "none"))]
static mut HOST_BASE: ScreenCursorBaseConstruct = unavailable_base;

/// Constructs the screen's provider-selection state in writable, aligned storage.
/// The base constructor may return a different object. Provider may be NULL;
/// owner is an opaque target-width pointer. Storage must accommodate 0x34 bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn screen_resource_selector_construct(
    storage: *mut u32, provider: *mut FrameworkObject, owner: u32,
) -> *mut u32 {
    #[cfg(target_os = "none")]
    let base: ScreenCursorBaseConstruct = core::mem::transmute(0x0816_f658usize);
    #[cfg(not(target_os = "none"))]
    let base = core::ptr::read_volatile(core::ptr::addr_of!(HOST_BASE));
    let screen = base(storage, provider);
    write_volatile(screen, 0x0898_7548);
    write_volatile(screen.cast::<u8>().add(0x24), 0);
    write_volatile(screen.add(10), 0x089a_6044);
    write_volatile(screen.add(11), 0);
    write_volatile(screen.cast::<u8>().add(0x30), 0);
    let selected = object_cast_to_class(provider, 6);
    write_volatile(screen.add(7), selected as usize as u32);
    write_volatile(screen.add(8), owner);
    screen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::registry::FrameworkObjectVtable;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    // Separate result verifies that derived writes use the base's returned object.
    unsafe extern "C" fn redirected_base(storage: *mut u32, _: *mut FrameworkObject) -> *mut u32 {
        storage.add(13)
    }
    unsafe extern "C" fn checked_provider(_: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, 6);
        0x1234_5678usize as *mut u8
    }
    unsafe extern "C" fn rejected_provider(_: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, 6);
        core::ptr::null_mut()
    }

    #[test]
    fn preserves_base_padding_and_uses_checked_provider_result() {
        let _guard = LOCK.lock();
        let vtable = FrameworkObjectVtable { unresolved_00: [0; 5], cast_to_class: checked_provider };
        let mut provider = FrameworkObject { vtable: &vtable };
        for owner in [0, u32::MAX, 0x0800_1000] {
            let mut storage = [0xa5a5_a5a5u32; 26];
            unsafe {
                HOST_BASE = redirected_base;
                let result = screen_resource_selector_construct(storage.as_mut_ptr(), &mut provider, owner);
                assert_eq!(result, storage.as_mut_ptr().add(13));
            }
            let mut expected = [0xa5a5_a5a5u32; 26];
            expected[13] = 0x0898_7548;
            expected[20] = 0x1234_5678;
            expected[21] = owner;
            expected[22] = 0xa5a5_a500;
            expected[23] = 0x089a_6044;
            expected[24] = 0;
            expected[25] = 0xa5a5_a500;
            assert_eq!(storage, expected);
        }
    }

    #[test]
    fn null_and_rejected_providers_remain_null() {
        let _guard = LOCK.lock();
        let vtable = FrameworkObjectVtable { unresolved_00: [0; 5], cast_to_class: rejected_provider };
        let mut provider = FrameworkObject { vtable: &vtable };
        for input in [core::ptr::null_mut(), &mut provider as *mut FrameworkObject] {
            let mut storage = [u32::MAX; 26];
            unsafe {
                HOST_BASE = redirected_base;
                screen_resource_selector_construct(storage.as_mut_ptr(), input, 0);
            }
            assert_eq!(storage[20], 0);
            assert_eq!(storage[21], 0);
            assert_eq!(storage[22], 0xffff_ff00);
            assert_eq!(storage[25], 0xffff_ff00);
        }
    }
}

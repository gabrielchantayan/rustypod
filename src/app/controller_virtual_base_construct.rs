//! Construction and registration of a controller's two virtual bases.

use core::ptr::{read_volatile, write_volatile};
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

type ConstructBase = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;
type Getter = unsafe extern "C" fn() -> *mut u8;
type Register = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ControllerVirtualBaseConstructOps {
    pub construct_base: ConstructBase,
    pub browse: Getter,
    pub media: Getter,
    pub settings: Getter,
}

#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_VIRTUAL_BASE_CONSTRUCT_OPS: ControllerVirtualBaseConstructOps =
    ControllerVirtualBaseConstructOps {
        construct_base: super::silver_controller::silver_controller_construct,
        browse: super::singletons::photo_browse_slideshow_get,
        media: super::singletons::lazy_singleton_0x8c_interface_get,
        settings: super::singletons::singleton_class_6200,
    };

#[inline(always)]
unsafe fn virtual_base(this: *mut u8, prefix_words: usize) -> *mut u8 {
    let vtable = read_volatile(this.cast::<u32>()) as usize as *const i32;
    this.offset(read_volatile(vtable.sub(prefix_words)) as isize)
}

#[inline(always)]
unsafe fn register(service: *mut u8, slot: usize, base: *mut u8) {
    // Native host function pointers; on ARM each slot is exactly four bytes.
    let table = read_volatile(service.cast::<*const Register>());
    (read_volatile(table.add(slot)))(service, base);
}

/// Original `FUN_0810d8a0` at **0x0810d8a0**, **212 bytes** through
/// 0x0810d974 (the next function begins with `cmp r0,#0`). Raw A32 words
/// contain **4 plain BL, 0 predicated BL, and 2 register BLX** instructions.
/// Full-image decoding finds **2 plain incoming BL and 0 predicated BL**.
///
/// Constructs the silver-controller base, installs the supplied three-word
/// construction-vtable group (primary and two offset-selected virtual bases),
/// stores the low byte of the mode, initializes two values to 25 and clears
/// the derived state. Caches the photo-browse singleton, then registers the
/// first virtual base through the media interface's slot 0 and the second
/// through class 0x6200's slot +0x98. Re-reads virtual offsets after callbacks.
/// No unproven class or registration-method identity is assigned.
///
/// Deviations: host-only getter/base seams and native-width service vtables;
/// target calls the four existing ports directly. Object words and supplied
/// construction tables remain 32-bit on every target. No behavioral change.
///
/// # Safety
/// The base constructor's inputs must be valid. Its returned object must be
/// aligned and writable through +0x14f and at both signed virtual offsets.
/// `vtables` supplies three readable words; primary vtables have readable
/// signed offsets at -12 and -16. Services and their invoked slots are valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_virtual_base_construct(
    this: *mut u8, vtables: *const u32, name: *const u8, mode: u32,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    let (construct_base, browse, media, settings): (ConstructBase, Getter, Getter, Getter) = (
        super::silver_controller::silver_controller_construct,
        super::singletons::photo_browse_slideshow_get,
        super::singletons::lazy_singleton_0x8c_interface_get,
        super::singletons::singleton_class_6200,
    );
    #[cfg(not(target_os = "none"))]
    let (construct_base, browse, media, settings) = {
        let ops = read_volatile(addr_of!(CONTROLLER_VIRTUAL_BASE_CONSTRUCT_OPS));
        (ops.construct_base, ops.browse, ops.media, ops.settings)
    };
    let this = construct_base(this, name);
    write_volatile(this.cast::<u32>(), read_volatile(vtables));
    write_volatile(virtual_base(this, 3).cast::<u32>(), read_volatile(vtables.add(1)));
    write_volatile(virtual_base(this, 4).cast::<u32>(), read_volatile(vtables.add(2)));
    write_volatile(this.add(0xb0), mode as u8);
    write_volatile(this.add(0xb4).cast::<u32>(), 25);
    write_volatile(this.add(0xb8).cast::<u32>(), 25);
    for offset in [0xbc, 0xc0, 0xc4, 0x11c] {
        write_volatile(this.add(offset).cast::<u32>(), 0);
    }
    write_volatile(this.add(0x13c).cast::<u32>(), browse() as usize as u32);
    for offset in 0x140..=0x144 { write_volatile(this.add(offset), 0); }
    write_volatile(this.add(0x148).cast::<u32>(), 0);
    write_volatile(this.add(0x14c).cast::<u32>(), 0);
    let service = media();
    register(service, 0, virtual_base(this, 3));
    let service = settings();
    register(service, 0x98 / 4, virtual_base(this, 4));
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut OBJECT: *mut u8 = core::ptr::null_mut();
    static mut PREFIX: *mut i32 = core::ptr::null_mut();
    static mut MEDIA: *mut u8 = core::ptr::null_mut();
    static mut SETTINGS: *mut u8 = core::ptr::null_mut();
    static mut FIRST_OFFSET: isize = 0;
    static mut SECOND_OFFSET: isize = 0;

    unsafe extern "C" fn construct(this: *mut u8, _: *const u8) -> *mut u8 {
        this.add(0x200)
    }
    unsafe extern "C" fn browse() -> *mut u8 { 0x12345678usize as *mut u8 }
    unsafe extern "C" fn media() -> *mut u8 { MEDIA }
    unsafe extern "C" fn settings() -> *mut u8 { SETTINGS }
    unsafe extern "C" fn first(_: *mut u8, base: *mut u8) {
        FIRST_OFFSET = base.offset_from(OBJECT);
        write_volatile(base.cast::<u32>(), 0x11223344);
        // Registration can replace the second virtual-base offset.
        write_volatile(PREFIX, 0x154);
    }
    unsafe extern "C" fn second(_: *mut u8, base: *mut u8) {
        SECOND_OFFSET = base.offset_from(OBJECT);
        write_volatile(base.cast::<u32>(), 0x55667788);
    }

    #[test]
    fn initializes_exact_bytes_and_reloads_signed_virtual_offsets_after_registration() {
        let _lock = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONTROLLER_VIRTUAL_BASE_CONSTRUCT, 4096,
        ) else { return; };
        let mut media_table = [first as Register; 1];
        let mut settings_table = [first as Register; 39];
        settings_table[38] = second;
        let mut media_object = media_table.as_mut_ptr();
        let mut settings_object = settings_table.as_mut_ptr();
        unsafe {
            let previous = read_volatile(addr_of!(CONTROLLER_VIRTUAL_BASE_CONSTRUCT_OPS));
            CONTROLLER_VIRTUAL_BASE_CONSTRUCT_OPS = ControllerVirtualBaseConstructOps {
                construct_base: construct, browse, media, settings,
            };
            MEDIA = (&mut media_object as *mut *mut Register).cast();
            SETTINGS = (&mut settings_object as *mut *mut Register).cast();
            OBJECT = slab.add(0x200);
            PREFIX = slab.add(0x800).cast();
            for (offset, mode) in [(0x150i32, 0u32), (-4, 0x1ff), (0x150, 0x100)] {
                core::ptr::write_bytes(slab, 0xa5, 0x800);
                write_volatile(PREFIX, 0x158);
                write_volatile(PREFIX.add(1), offset);
                let table = [PREFIX.add(4) as usize as u32, 0xaabbccdd, 0xeeff0011];
                let result = controller_virtual_base_construct(slab, table.as_ptr(), core::ptr::null(), mode);
                let mut expected = [0xa5u8; 0x180];
                let start = 0x10usize;
                let mut word = |offset: isize, value: u32| {
                    let pos = (start as isize + offset) as usize;
                    expected[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
                };
                word(0, table[0]);
                word(offset as isize, 0x11223344);
                word(0x158, table[2]);
                word(0x154, 0x55667788);
                word(0xb4, 25); word(0xb8, 25);
                for offset in [0xbc, 0xc0, 0xc4, 0x11c, 0x148, 0x14c] { word(offset, 0); }
                word(0x13c, 0x12345678);
                expected[start + 0xb0] = mode as u8;
                expected[start + 0x140..=start + 0x144].fill(0);
                assert_eq!(result, OBJECT);
                assert_eq!(FIRST_OFFSET, offset as isize);
                assert_eq!(SECOND_OFFSET, 0x154);
                assert_eq!(core::slice::from_raw_parts(OBJECT.sub(start), expected.len()), expected);
            }
            CONTROLLER_VIRTUAL_BASE_CONSTRUCT_OPS = previous;
        }
    }
}

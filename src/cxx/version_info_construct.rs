//! Version-info object constructor.
//!
//! `version_info_construct` — original: `FUN_08165b84` @ `0x08165b84`.
//!
//! Raw `osos.dec` establishes the 120-byte extent `0x08165b84..0x08165bfc`:
//! 116 bytes of instructions followed by its one-word literal pool; the next
//! function starts at `0x08165bfc` with `bx lr`. The instruction body has
//! **three plain, unconditional `bl` calls** and no predicated calls. It
//! classifies `selector`, invokes the base object constructor with the quotient
//! and remainder of `size / 16`, replaces the base vtable, then finalizes word
//! +24 from the second classification.
//!
//! Deliberate deviations: the three individually verified, unported retailOS
//! workers remain ARM literal veneers and replaceable host seams. Their names
//! describe only the observed constructor roles; no concrete class identity
//! survives in the image.

#[cfg(not(target_arch = "arm"))]
use core::ptr;

const VERSION_INFO_VTABLE: u32 = 0x0898_7eb0;

/// The observed 28-byte ARM object layout. Pointer-sized fields are represented
/// as words so host layout cannot alter target offsets.
#[repr(C)]
pub struct VersionInfo {
    vtable: u32,
    tag: u32,
    size_blocks: u32,
    size_remainder: u32,
    selector_class: u32,
    extra: u32,
    packed_metadata: u32,
}

pub type VersionSizeClass = unsafe extern "C" fn(*mut VersionInfo, u32) -> u32;
pub type VersionInfoBaseConstruct = unsafe extern "C" fn(*mut VersionInfo, u32, u32, u32, u32, u32) -> *mut VersionInfo;
pub type VersionInfoFinalize = unsafe extern "C" fn(*mut VersionInfo, u32, u32, u32, u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn size_class_zero(_object: *mut VersionInfo, _selector: u32) -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn base_construct_identity(object: *mut VersionInfo, _tag: u32, _blocks: u32, _remainder: u32, _class: u32, _extra: u32) -> *mut VersionInfo { object }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn finalize_noop(_object: *mut VersionInfo, _tag: u32, _size: u32, _class: u32, _extra: u32) {}

#[cfg(not(target_arch = "arm"))]
pub static mut VERSION_SIZE_CLASS: VersionSizeClass = size_class_zero;
#[cfg(not(target_arch = "arm"))]
pub static mut VERSION_INFO_BASE_CONSTRUCT: VersionInfoBaseConstruct = base_construct_identity;
#[cfg(not(target_arch = "arm"))]
pub static mut VERSION_INFO_FINALIZE: VersionInfoFinalize = finalize_noop;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_version_size_class(object: *mut VersionInfo, selector: u32) -> u32;
    fn retail_version_info_base_construct(object: *mut VersionInfo, tag: u32, blocks: u32, remainder: u32, class: u32, extra: u32) -> *mut VersionInfo;
    fn retail_version_info_finalize(object: *mut VersionInfo, tag: u32, size: u32, class: u32, extra: u32);
}
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_version_size_class(object: *mut VersionInfo, selector: u32) -> u32 {
    ptr::read_volatile(ptr::addr_of!(VERSION_SIZE_CLASS))(object, selector)
}
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_version_info_base_construct(object: *mut VersionInfo, tag: u32, blocks: u32, remainder: u32, class: u32, extra: u32) -> *mut VersionInfo {
    ptr::read_volatile(ptr::addr_of!(VERSION_INFO_BASE_CONSTRUCT))(object, tag, blocks, remainder, class, extra)
}
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_version_info_finalize(object: *mut VersionInfo, tag: u32, size: u32, class: u32, extra: u32) {
    ptr::read_volatile(ptr::addr_of!(VERSION_INFO_FINALIZE))(object, tag, size, class, extra)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_version_size_class
retail_version_size_class:
    ldr pc, [pc, #-4]
    .word 0x081659cc
    .globl retail_version_info_base_construct
retail_version_info_base_construct:
    ldr pc, [pc, #-4]
    .word 0x082779c4
    .globl retail_version_info_finalize
retail_version_info_finalize:
    ldr pc, [pc, #-4]
    .word 0x08165a18
"#);

/// Constructs the version-info object at `object` and returns the base constructor result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn version_info_construct(object: *mut VersionInfo, tag: u32, size: u32, selector: u32, extra: u32) -> *mut VersionInfo {
    let initial_class = retail_version_size_class(object, selector);
    let result = retail_version_info_base_construct(object, tag, size >> 4, size & 15, initial_class, extra);
    (*result).vtable = VERSION_INFO_VTABLE;
    let final_class = retail_version_size_class(result, selector);
    retail_version_info_finalize(result, tag, size, final_class, extra);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CLASS_ARGS: [(usize, u32); 2] = [(0, 0); 2];
    static mut CLASS_COUNT: usize = 0;
    static mut BASE_ARGS: (usize, u32, u32, u32, u32, u32) = (0, 0, 0, 0, 0, 0);
    static mut FINAL_ARGS: (usize, u32, u32, u32, u32) = (0, 0, 0, 0, 0);
    static mut RETURNED: *mut VersionInfo = core::ptr::null_mut();

    unsafe extern "C" fn classify(object: *mut VersionInfo, selector: u32) -> u32 {
        CLASS_ARGS[CLASS_COUNT] = (object as usize, selector);
        let value = [3, 5][CLASS_COUNT];
        CLASS_COUNT += 1;
        value
    }
    unsafe extern "C" fn base(object: *mut VersionInfo, tag: u32, blocks: u32, remainder: u32, class: u32, extra: u32) -> *mut VersionInfo {
        BASE_ARGS = (object as usize, tag, blocks, remainder, class, extra);
        RETURNED
    }
    unsafe extern "C" fn finalize(object: *mut VersionInfo, tag: u32, size: u32, class: u32, extra: u32) {
        FINAL_ARGS = (object as usize, tag, size, class, extra);
    }

    #[test]
    fn constructor_routes_split_size_and_replaces_the_returned_objects_vtable() {
        let _lock = LOCK.lock();
        let mut input = VersionInfo { vtable: 0, tag: 0, size_blocks: 0, size_remainder: 0, selector_class: 0, extra: 0, packed_metadata: 0 };
        let mut returned = VersionInfo { vtable: 0xfeed_face, tag: 0, size_blocks: 0, size_remainder: 0, selector_class: 0, extra: 0, packed_metadata: 0 };
        unsafe {
            CLASS_COUNT = 0;
            RETURNED = &mut returned;
            VERSION_SIZE_CLASS = classify;
            VERSION_INFO_BASE_CONSTRUCT = base;
            VERSION_INFO_FINALIZE = finalize;
            assert_eq!(version_info_construct(&mut input, 2, 4, 0x80, 0) as usize, &mut returned as *mut VersionInfo as usize);
            assert_eq!(BASE_ARGS, (&mut input as *mut VersionInfo as usize, 2, 0, 4, 3, 0));
            assert_eq!(CLASS_ARGS, [(&mut input as *mut VersionInfo as usize, 0x80), (&mut returned as *mut VersionInfo as usize, 0x80)]);
            assert_eq!(FINAL_ARGS, (&mut returned as *mut VersionInfo as usize, 2, 4, 5, 0));
            assert_eq!(returned.vtable, VERSION_INFO_VTABLE);
            assert_eq!(input.vtable, 0);
        }
    }
}

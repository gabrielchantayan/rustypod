//! Version-info object constructor.
//!
//! `version_info_construct` — original: `FUN_08165b84` @ `0x08165b84`.
//!
//! Raw `osos.dec` establishes the 120-byte extent `0x08165b84..0x08165bfc`:
//! 116 bytes of instructions followed by its one-word literal pool; the next
//! function starts at `0x08165bfc` with `bx lr`. The instruction body has
//! **four plain, unconditional `bl` calls** and no predicated calls. It
//! classifies `selector`, invokes the base object constructor with the quotient
//! and remainder of `size / 16`, replaces the base vtable, then finalizes word
//! +24 from the second classification.
//!
//! Deliberate deviations: the two remaining unported retailOS workers use ARM
//! literal veneers and replaceable host seams. Classification uses the Rust
//! port below. Worker names describe only observed constructor roles; no
//! concrete class identity survives in the image.

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

/// Classifies a version selector without reading or modifying `object`.
///
/// Original: `FUN_081659cc` @ `0x081659cc`, **76 bytes**, ending at the next
/// real entry `0x08165a18`. Raw A32 decoding verifies zero outgoing plain or
/// predicated BLs; two incoming plain BLs at `0x08165ba0` and `0x08165bd4`,
/// zero incoming predicated BLs. Compare selector against 0x40, then test
/// 0x10/0x20 below it or 0x60/0x80 above it; return classes 1..5 respectively,
/// otherwise zero. r0 on entry is ignored; the full r1 word is compared.
/// Deliberate deviations: express the decision tree as a match; retain the
/// unused object argument for the original ABI. No table access or validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn version_size_class(_object: *mut VersionInfo, selector: u32) -> u32 {
    match selector {
        0x10 => 1,
        0x20 => 2,
        0x40 => 3,
        0x60 => 4,
        0x80 => 5,
        _ => 0,
    }
}
pub type VersionInfoBaseConstruct = unsafe extern "C" fn(*mut VersionInfo, u32, u32, u32, u32, u32) -> *mut VersionInfo;
pub type VersionInfoFinalize = unsafe extern "C" fn(*mut VersionInfo, u32, u32, u32, u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn base_construct_identity(object: *mut VersionInfo, _tag: u32, _blocks: u32, _remainder: u32, _class: u32, _extra: u32) -> *mut VersionInfo { object }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn finalize_noop(_object: *mut VersionInfo, _tag: u32, _size: u32, _class: u32, _extra: u32) {}

#[cfg(not(target_arch = "arm"))]
pub static mut VERSION_INFO_BASE_CONSTRUCT: VersionInfoBaseConstruct = base_construct_identity;
#[cfg(not(target_arch = "arm"))]
pub static mut VERSION_INFO_FINALIZE: VersionInfoFinalize = finalize_noop;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_version_info_base_construct(object: *mut VersionInfo, tag: u32, blocks: u32, remainder: u32, class: u32, extra: u32) -> *mut VersionInfo;
    fn retail_version_info_finalize(object: *mut VersionInfo, tag: u32, size: u32, class: u32, extra: u32);
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
    let initial_class = version_size_class(object, selector);
    let result = retail_version_info_base_construct(object, tag, size >> 4, size & 15, initial_class, extra);
    (*result).vtable = VERSION_INFO_VTABLE;
    let final_class = version_size_class(result, selector);
    retail_version_info_finalize(result, tag, size, final_class, extra);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_exact_selectors_and_rejects_every_other_byte() {
        let selectors = [0x10, 0x20, 0x40, 0x60, 0x80];
        for selector in 0..=255 {
            let expected = selectors.iter().position(|&value| value == selector)
                .map_or(0, |index| index as u32 + 1);
            assert_eq!(version_size_class(core::ptr::null_mut(), selector), expected);
        }
    }

    #[test]
    fn compares_full_word_and_never_dereferences_object() {
        for selector in [0x100, 0x110, 0x120, 0x140, 0x160, 0x180,
                         0x7fff_ffff, 0x8000_0000, 0xffff_ff80, u32::MAX] {
            assert_eq!(version_size_class(core::ptr::without_provenance_mut(1), selector), 0);
        }
        assert_eq!(version_size_class(core::ptr::without_provenance_mut(1), 0x80), 5);
    }
}

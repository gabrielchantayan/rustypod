//! `ui_descriptor_init_static_span` — original: `FUN_0811f720` @
//! `0x0811f720` (28 bytes, including the literal at `0x0811f73c`).
//!
//! Initializes only the three observed fields of a caller-owned UI descriptor:
//! it stores the fixed retailOS pointer `0x0898_2f40` at +0x00, that pointer
//! plus 0x20 at +0x04, and the u16 value `0x0400` at +0x0c. Callers then fill
//! other fields, so their layout and the intervening bytes remain deliberately
//! unnamed and untouched.
//!
//! Deviations: none. The original requires the supplied object to be aligned
//! for its word and halfword stores; this port preserves that requirement.

/// RetailOS static base pointer loaded from the literal at `0x0811f73c`.
pub const UI_DESCRIPTOR_STATIC_BASE: u32 = 0x0898_2f40;
/// The second pointer the original derives from [`UI_DESCRIPTOR_STATIC_BASE`].
pub const UI_DESCRIPTOR_STATIC_SPAN_END: u32 = UI_DESCRIPTOR_STATIC_BASE + 0x20;
/// The u16 field value the original writes at offset +0x0c.
pub const UI_DESCRIPTOR_STATIC_EXTENT: u16 = 0x0400;

/// Offset of the fixed base pointer within the caller-owned descriptor.
pub const UI_DESCRIPTOR_STATIC_BASE_OFFSET: usize = 0x00;
/// Offset of the fixed base-plus-0x20 pointer within the descriptor.
pub const UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET: usize = 0x04;
/// Offset of the u16 `0x0400` field within the descriptor.
pub const UI_DESCRIPTOR_STATIC_EXTENT_OFFSET: usize = 0x0c;

/// Writes the observed static UI descriptor fields into `descriptor`.
///
/// The pointer must be valid and aligned for the 32-bit stores at +0x00/+0x04
/// and the 16-bit store at +0x0c. No other part of the descriptor layout is
/// known or accessed.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_descriptor_init_static_span(descriptor: *mut u8) {
    descriptor
        .add(UI_DESCRIPTOR_STATIC_BASE_OFFSET)
        .cast::<u32>()
        .write(UI_DESCRIPTOR_STATIC_BASE);
    descriptor
        .add(UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET)
        .cast::<u32>()
        .write(UI_DESCRIPTOR_STATIC_SPAN_END);
    descriptor
        .add(UI_DESCRIPTOR_STATIC_EXTENT_OFFSET)
        .cast::<u16>()
        .write(UI_DESCRIPTOR_STATIC_EXTENT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct DescriptorBytes([u8; 0x10]);

    #[test]
    fn field_offsets_match_the_original_stores() {
        assert_eq!(UI_DESCRIPTOR_STATIC_BASE_OFFSET, 0x00);
        assert_eq!(UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET, 0x04);
        assert_eq!(UI_DESCRIPTOR_STATIC_EXTENT_OFFSET, 0x0c);
        assert_eq!(core::mem::size_of_val(&UI_DESCRIPTOR_STATIC_BASE), 4);
        assert_eq!(core::mem::size_of_val(&UI_DESCRIPTOR_STATIC_EXTENT), 2);
    }

    #[test]
    fn writes_all_and_only_the_observed_fields() {
        let mut descriptor = DescriptorBytes([0xa5; 0x10]);

        unsafe { ui_descriptor_init_static_span(descriptor.0.as_mut_ptr()) };

        let base = unsafe {
            descriptor
                .0
                .as_ptr()
                .add(UI_DESCRIPTOR_STATIC_BASE_OFFSET)
                .cast::<u32>()
                .read()
        };
        let span_end = unsafe {
            descriptor
                .0
                .as_ptr()
                .add(UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET)
                .cast::<u32>()
                .read()
        };
        let extent = unsafe {
            descriptor
                .0
                .as_ptr()
                .add(UI_DESCRIPTOR_STATIC_EXTENT_OFFSET)
                .cast::<u16>()
                .read()
        };

        assert_eq!(base, 0x0898_2f40);
        assert_eq!(span_end, 0x0898_2f60);
        assert_eq!(extent, 0x0400);
        assert_eq!(descriptor.0[0x08..0x0c], [0xa5; 4]);
        assert_eq!(descriptor.0[0x0e..0x10], [0xa5; 2]);
    }
}

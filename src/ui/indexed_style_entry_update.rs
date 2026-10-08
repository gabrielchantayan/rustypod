//! Indexed text-style entry update — retailOS `FUN_0812863c` at 0x0812863c.
//! True extent: 124 bytes, ending at the next prologue at 0x081286b8.
//! Raw ARM scan: two plain inbound BLs, zero predicated; two plain outgoing
//! BLs to the already ported color_copy (0x082720e8), zero predicated.
//!
//! Updates nonzero scalar and nonnull optional fields in order: 16-bit value,
//! font-style byte, foreground RGBA, background RGBA. ORs presence bits 1/2/4/8
//! after each update, retaining all previous flags. The sorted-list constructor
//! at 0x081287c8 establishes the 0x18-byte entry layout; the renderer at
//! 0x081286b8 consumes the colors and font-style byte. No more specific meaning
//! is assigned to the 16-bit value without evidence.
//!
//! Deliberate deviations: raw byte offsets keep the target's two 32-bit link
//! fields host-independent; volatile accesses preserve alias-sensitive order.
//! Reuses color_copy, including its forward-overlap behavior; no new seam.

use crate::cxx::color_copy::color_copy;

/// # Safety
/// `entry` must address a writable 0x18-byte entry aligned to at least two
/// bytes. Each nonnull source must address one (font_style) or four (colors)
/// readable bytes. Sources may alias the entry; accesses occur in stock order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_style_entry_update(
    entry: *mut u8,
    value: u32,
    font_style: *const u8,
    foreground: *const u8,
    background: *const u8,
) {
    let presence = entry.add(0x14).cast::<u16>();
    if value != 0 {
        entry.add(0x10).cast::<u16>().write_volatile(value as u16);
        presence.write_volatile(presence.read_volatile() | 1);
    }
    if !font_style.is_null() {
        entry.add(0x12).write_volatile(font_style.read_volatile());
        presence.write_volatile(presence.read_volatile() | 2);
    }
    if !foreground.is_null() {
        color_copy(entry.add(8), foreground);
        presence.write_volatile(presence.read_volatile() | 4);
    }
    if !background.is_null() {
        color_copy(entry.add(12), background);
        presence.write_volatile(presence.read_volatile() | 8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Bytes([u8; 32]);

    // Independent byte-level model, including ordered forward color copies.
    fn reference(bytes: &mut [u8; 32], value: u32, sources: [Option<usize>; 3]) {
        let mut mark = |bytes: &mut [u8; 32], bit: u16| {
            let flags = u16::from_le_bytes([bytes[20], bytes[21]]) | bit;
            bytes[20..22].copy_from_slice(&flags.to_le_bytes());
        };
        if value != 0 {
            bytes[16..18].copy_from_slice(&(value as u16).to_le_bytes());
            mark(bytes, 1);
        }
        if let Some(src) = sources[0] {
            bytes[18] = bytes[src];
            mark(bytes, 2);
        }
        for (index, dst, bit) in [(1, 8, 4), (2, 12, 8)] {
            if let Some(src) = sources[index] {
                for offset in 0..4 {
                    bytes[dst + offset] = bytes[src + offset];
                }
                mark(bytes, bit);
            }
        }
    }

    fn check(value: u32, sources: [Option<usize>; 3], flags: u16) {
        let mut actual = Bytes(core::array::from_fn(|n| (n as u8).wrapping_mul(37)));
        actual.0[20..22].copy_from_slice(&flags.to_le_bytes());
        let mut expected = actual.0;
        reference(&mut expected, value, sources);
        let base = actual.0.as_mut_ptr();
        let pointers = sources.map(|src| match src {
            Some(offset) => unsafe { base.add(offset) as *const u8 },
            None => core::ptr::null(),
        });
        unsafe { indexed_style_entry_update(base, value, pointers[0], pointers[1], pointers[2]); }
        assert_eq!(actual.0, expected, "value={value:#x}, sources={sources:?}, flags={flags:#x}");
    }

    #[test]
    fn optional_fields_truncation_and_existing_presence() {
        for flags in [0, 0xa5f0, 0xffff] {
            for value in [0, 1, 0xffff, 0x10000, 0xffff_ffff] {
                for mask in 0..8 {
                    check(value, [
                        (mask & 1 != 0).then_some(24),
                        (mask & 2 != 0).then_some(25),
                        (mask & 4 != 0).then_some(28),
                    ], flags);
                }
            }
        }
    }

    #[test]
    fn aliased_sources_observe_prior_scalar_color_and_flag_writes() {
        for font in 0..24 {
            for foreground in 0..=28 {
                for background in 0..=28 {
                    check(0x12345678, [Some(font), Some(foreground), Some(background)], 0x8000);
                }
            }
        }
    }
}

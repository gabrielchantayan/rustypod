//! Query mask translation and backend assignment.

/// query_object_set_masks — `FUN_0813d064` @ `0x0813d064`.
/// True extent: 52 bytes, ending at the independent wrapper `0x0813d098`,
/// not Ghidra's reported 68. Raw A32 decoding finds two plain BLs and zero
/// predicated BLs in the body; inbound BLs are at `0x080febb4` and
/// `0x082373e0` (both unconditional). A final B targets `0x080cbed4`.
///
/// Translate each input through the mapping verified at `0x080c0608`:
/// preserve bits 0..3 and 21; move bits 4,5,6,7 to 5,6,8,15. Discard
/// all other bits. Load the backend pointer from query +0x40, store the
/// first translated mask at backend +0xe30 and the second at +0xe34,
/// then return zero. Callers supply (0x32, 0) or a literal mask and zero.
/// The converter uses only r0/r1 and preserves the original's saved r3.
///
/// Deliberate deviation: inline the verified pure converter and trivial
/// setter rather than create two firmware seams. Query pointers stay u32
/// on hosts; there is no validation, dereference through a proxy, or merge.
///
/// # Safety
/// `query + 0x40` must contain an aligned, readable target-width backend
/// pointer whose aligned words at +0xe30 and +0xe34 are writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn query_object_set_masks(query: *const u8, first: u32, second: u32) -> u32 {
    let translate = |mask: u32| {
        (mask & 0x0020_000f) | ((mask & 0x30) << 1)
            | ((mask & 0x40) << 2) | ((mask & 0x80) << 8)
    };
    let second = translate(second);
    let first = translate(first);
    let backend = query.add(0x40).cast::<u32>().read() as usize as *mut u8;
    backend.add(0xe30).cast::<u32>().write(first);
    backend.add(0xe34).cast::<u32>().write(second);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    fn reference(mask: u32) -> u32 {
        let mut result = 0;
        for (source, destination) in [(0, 0), (1, 1), (2, 2), (3, 3),
            (4, 5), (5, 6), (6, 8), (7, 15), (21, 21)] {
            if mask & (1 << source) != 0 { result |= 1 << destination; }
        }
        result
    }

    #[test]
    fn translates_and_replaces_both_masks_without_touching_neighbors() {
        let Some(slab) = try_map_u32_slab(hints::QUERY_OBJECT_SET_MASKS, 0x4000) else {
            assert!(note_missing_u32_fixture("ui/query_object_set_masks"));
            return;
        };
        unsafe {
            let query = slab;
            let backend = slab.add(0x100);
            query.add(0x40).cast::<u32>().write(backend as usize as u32);
            query.add(0x44).cast::<u32>().write(0xdead_beef);
            let words = backend.cast::<u32>();
            // Exhaust low-byte combinations with bit 21 both clear and set;
            // one-hot inputs also prove every unsupported bit is discarded.
            let inputs = (0..256).flat_map(|v| [v, v | 0x200000])
                .chain((0..32).map(|bit| 1u32 << bit))
                .chain([u32::MAX, 0x32, 0]);
            for first in inputs {
                let second = !first;
                words.add(0xe2c / 4).write(0x12345678);
                words.add(0xe30 / 4).write(u32::MAX);
                words.add(0xe34 / 4).write(u32::MAX);
                words.add(0xe38 / 4).write(0x87654321);
                assert_eq!(query_object_set_masks(query, first, second), 0);
                assert_eq!(words.add(0xe30 / 4).read(), reference(first));
                assert_eq!(words.add(0xe34 / 4).read(), reference(second));
                assert_eq!(words.add(0xe2c / 4).read(), 0x12345678);
                assert_eq!(words.add(0xe38 / 4).read(), 0x87654321);
                assert_eq!(query.add(0x44).cast::<u32>().read(), 0xdead_beef);
            }
        }
    }
}

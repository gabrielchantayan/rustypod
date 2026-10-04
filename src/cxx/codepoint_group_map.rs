//! Codepoint group-map population and its retailOS singleton accessor.

use super::string_object::utf8_next_codepoint;

/// Populate a codepoint-to-group byte map — original `FUN_0820b2c4` at
/// 0x0820b2c4. True extent: 120 bytes through 0x0820b33c (116 bytes of
/// instructions and the 0x1ff literal at 0x0820b338). Raw ARM verifies
/// one unconditional BL at 0x0820b2f4 to utf8_next_codepoint, zero predicated
/// BLs; Ghidra's reported two call sites are not present in the bytes.
///
/// Walk a NULL-terminated target-width array of UTF-8 string pointers,
/// writing (first_group + string_index) modulo 256 at embedded_table[codepoint]
/// until the decoder returns zero. Later groups overwrite earlier entries;
/// all other bytes are preserved. Then set header words to 0, 511, and the
/// address of the embedded table at +12. No deliberate deviations.
///
/// # Safety
/// `map` must be word-aligned, writable through +12 plus every decoded
/// codepoint. `groups` points to a readable u32 array-address word; the array
/// and its strings must be readable through their terminators, including the
/// decoder's unchecked multibyte reads. Stored pointers use the target's u32 ABI.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codepoint_group_map_populate(
    map: *mut u32,
    first_group: u32,
    groups: *const u32,
) {
    let mut index = 0usize;
    loop {
        let array = *groups as usize as *const u32;
        let string = *array.add(index);
        if string == 0 { break; }
        let mut cursor = string as usize as *const u8;
        let label = first_group.wrapping_add(index as u32) as u8;
        loop {
            let codepoint = utf8_next_codepoint(&mut cursor);
            if codepoint == 0 { break; }
            map.cast::<u8>().add(12 + codepoint as usize).write(label);
        }
        index += 1;
    }
    map.write(0);
    map.add(1).write(511);
    map.add(2).write(map.cast::<u8>().add(12) as usize as u32);
}

#[repr(C)]
struct GroupMapState {
    ready: u8,
    padding: [u8; 3],
    guard: u32,
}

type MapConstructor = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(not(target_os = "none"))]
static mut GROUP_MAP_CONTEXT: Option<(*mut GroupMapState, *mut u32, u32, u32, MapConstructor)> = None;

/// Get the singleton codepoint group map — `FUN_0820b234` @ 0x0820b234.
/// True size: 144 bytes (128 instruction bytes and 16 literal bytes), ending
/// at the real function boundary 0x0820b2c4. Raw words establish five plain
/// outbound BLs, zero predicated BLs, and two plain inbound BLs.
///
/// Test guard bit zero; an accepted ADS acquire constructs the fixed map at
/// 0x08ad7e08 using the unported constructor at 0x0820b33c, then releases the
/// guard. Independently, if the ready byte is clear, publish it BEFORE
/// populating the letter and digit groups (bases 0x41 and 0x30 respectively).
/// Always return the fixed map, ignoring the constructor's return.
/// No target behavioral deviations. Host builds require an installed context
/// in place of firmware RAM and the unavailable constructor.
///
/// # Safety
/// Firmware state, map, group arrays and strings must be accessible; decoded
/// codepoints must fit the allocated map. Calls must be externally serialized
/// as in the original single-threaded ADS guard implementation.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codepoint_group_map_get() -> *mut u32 {
    #[cfg(target_os = "none")]
    let (state, map, letters, digits, construct) = (
        0x089d01f0usize as *mut GroupMapState,
        0x08ad7e08usize as *mut u32,
        0x089d01fcu32, 0x089d0268u32,
        core::mem::transmute::<usize, MapConstructor>(0x0820b33c),
    );
    #[cfg(not(target_os = "none"))]
    let (state, map, letters, digits, construct) =
        core::ptr::read(core::ptr::addr_of!(GROUP_MAP_CONTEXT))
            .expect("codepoint_group_map_get requires firmware context");
    let guard = core::ptr::addr_of_mut!((*state).guard);
    if core::ptr::read_volatile(guard) & 1 == 0
        && crate::runtime::cxa_guard::cxa_guard_acquire(guard) != 0 {
        construct(map);
        crate::runtime::cxa_guard::cxa_guard_release(guard);
    }
    if (*state).ready == 0 {
        (*state).ready = 1;
        codepoint_group_map_populate(map, 0x41, &letters);
        codepoint_group_map_populate(map, 0x30, &digits);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    unsafe extern "C" fn modeled_constructor(map: *mut u32) -> *mut u32 {
        let (state, _, _, _, _) = GROUP_MAP_CONTEXT.unwrap();
        assert_eq!((*state).guard, 1);
        map.cast::<u8>().write_bytes(0, 524);
        // The accessor must ignore this return value.
        core::ptr::null_mut()
    }

    #[test]
    fn singleton_initialization_precedence_and_independent_flags() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CODEPOINT_GROUP_MAP_GET, 0x2000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("codepoint_group_map_get"));
            return;
        };
        unsafe {
            let map = slab.cast::<u32>();
            let mut state = GroupMapState { ready: 0, padding: [0; 3], guard: 0 };
            let letters = slab.add(0x1000).cast::<u32>();
            let digits = letters.add(3);
            let text = slab.add(0x1100);
            core::ptr::copy_nonoverlapping(b"Aa\0Bb\0A0\0".as_ptr(), text, 9);
            letters.write(text as usize as u32);
            letters.add(1).write(text.add(3) as usize as u32);
            letters.add(2).write(0);
            digits.write(text.add(6) as usize as u32);
            digits.add(1).write(0);
            GROUP_MAP_CONTEXT = Some((&mut state, map, letters as usize as u32,
                digits as usize as u32, modeled_constructor));
            slab.write_bytes(0xa5, 524);
            assert_eq!(codepoint_group_map_get(), map);
            assert_eq!((state.ready, state.guard), (1, 1));
            let table = slab.add(12);
            let mut expected = [0u8; 512];
            for (cp, group) in [(65, 48), (97, 65), (66, 66), (98, 66), (48, 48)] {
                expected[cp] = group;
            }
            assert_eq!(core::slice::from_raw_parts(table, 512), expected);
            assert_eq!(core::slice::from_raw_parts(map, 3),
                &[0, 511, table as usize as u32]);
            table.add(65).write(0x7e);
            assert_eq!(codepoint_group_map_get(), map);
            assert_eq!(table.add(65).read(), 0x7e);
            // Nonzero guard with bit zero clear refuses construction, but
            // the independent ready byte still causes population.
            state.guard = 2;
            state.ready = 0;
            table.add(500).write(0x7f);
            codepoint_group_map_get();
            assert_eq!((state.ready, state.guard), (1, 2));
            assert_eq!(table.add(500).read(), 0x7f);
            assert_eq!(table.add(65).read(), 48);
            // Ready does not suppress a needed constructor; no population
            // follows when ready was already set.
            state.guard = 0;
            codepoint_group_map_get();
            assert_eq!((state.ready, state.guard), (1, 1));
            assert_eq!(core::slice::from_raw_parts(slab, 524), [0u8; 524]);
            GROUP_MAP_CONTEXT = None;
        }
    }

    #[test]
    fn preserves_unmapped_bytes_overwrites_groups_and_stops_on_decoded_zero() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CODEPOINT_GROUP_MAP, 0x12000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("codepoint_group_map"));
            return;
        };
        unsafe {
            let map = slab.cast::<u32>();
            let array = slab.add(0x11000).cast::<u32>();
            let strings: [&[u8]; 5] = [
                b"A\xc3\xa9\xef\xbf\xbf\0", b"\0", b"AB\0",
                b"C\xf0\x80\x80D\0", b"E\xc0\x80F\0",
            ];
            for (index, text) in strings.iter().enumerate() {
                let dst = slab.add(0x11100 + index * 32);
                core::ptr::copy_nonoverlapping(text.as_ptr(), dst, text.len());
                array.add(index).write(dst as usize as u32);
            }
            array.add(strings.len()).write(0);
            let groups = array as usize as u32;
            slab.write_bytes(0xa5, 0x1000c);
            codepoint_group_map_populate(map, 0x1ff, &groups);
            assert_eq!(core::slice::from_raw_parts(map, 3),
                &[0, 511, slab.add(12) as usize as u32]);
            let mut expected = std::vec![0xa5u8; 65536];
            for (cp, label) in [(65, 1), (66, 1), (67, 2), (69, 3), (233, 255), (65535, 255)] {
                expected[cp] = label;
            }
            assert_eq!(core::slice::from_raw_parts(slab.add(12), 65536), expected);
            // Empty input still initializes the header without clearing the table.
            array.write(0);
            map.write(99);
            map.add(1).write(99);
            map.add(2).write(99);
            codepoint_group_map_populate(map, 42, &groups);
            assert_eq!(core::slice::from_raw_parts(map, 3),
                &[0, 511, slab.add(12) as usize as u32]);
            assert_eq!(core::slice::from_raw_parts(slab.add(12), 65536), expected);
        }
    }
}

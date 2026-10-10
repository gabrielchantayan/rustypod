//! Accessor for an indexed UI mode-state flag.

/// The mode-state pointer table (original global region @ `0x08b2_f648`).
///
/// The ARM literal at `0x080b64b8` names this table directly; each
/// `0x18c`-byte record begins with an object pointer. The table itself is
/// modeled as a replaceable target-global seam so host tests and firmware
/// integration can supply its storage. A volatile load prevents an unwired
/// target build from folding the null initial value into callers.
pub static mut MODE_STATE_OBJECT_TABLE: *const u8 = core::ptr::null();

#[inline(always)]
unsafe fn mode_state_object_table() -> *const u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(MODE_STATE_OBJECT_TABLE))
}

/// Byte stride between pointers in [`MODE_STATE_OBJECT_TABLE`] (`99 * 4`).
const MODE_STATE_RECORD_STRIDE: isize = 0x18c;

/// Byte offset of the status word in a selected object.
const MODE_STATE_STATUS_OFFSET: usize = 0x400;
/// Byte offset of the mode word in a selected object.
const MODE_STATE_FLAG_OFFSET: usize = 0x860;
/// Byte offset of the status code in a selected mode substate.
const MODE_STATE_SUBSTATE_CODE_OFFSET: usize = 0x14;

/// select_mode_substate — original: `FUN_080e1cc8` @ `0x080e1cc8`
/// (64 bytes).
///
/// Verified call count: three unconditional `bl` sites (`0x080db644`,
/// `0x080dd2b4`, and `0x080df5b8`); no predicated calls. Raw ARM returns
/// `object + selector * 0x20` for selectors 0–3, selects the irregular
/// offsets `0x100`, `0x180`, `0x200`, and `0x230` for selectors 4–7, and
/// returns null for every other selector.
///
/// Deliberate deviations: `wrapping_add` expresses the ARM address addition
/// without requiring a dereferenceable Rust allocation. The original has no
/// memory accesses, bounds checks, or null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn select_mode_substate(object: *mut u8, selector: u32) -> *mut u8 {
    if selector == 4 {
        return object.wrapping_add(0x100);
    }
    if selector == 5 {
        return object.wrapping_add(0x180);
    }
    if selector == 6 {
        return object.wrapping_add(0x200);
    }
    if selector == 7 {
        return object.wrapping_add(0x230);
    }
    if selector > 3 {
        return core::ptr::null_mut();
    }

    object.wrapping_add(selector as usize * 0x20)
}



/// indexed_mode_flag — original: `FUN_080b649c` @ `0x080b649c` (28 bytes).
///
/// Raw ARM: `mov r1,#0x63; smulbb r0,r0,r1; ldr r1,[pc,#0xc]; ldr
/// r0,[r1,r0,lsl #2]; ldr r0,[r0,#0x860]; and r0,r0,#0x1f; bx lr`.
/// It treats the low halfword of `index` as signed, addresses the object
/// pointer at `MODE_STATE_OBJECT_TABLE + index * 0x18c`, then returns the
/// low five bits of that object's mode word at `+0x860`. The mode's concrete
/// meaning is not recovered, so the name records only its indexed flag role.
///
/// # Safety
///
/// [`MODE_STATE_OBJECT_TABLE`] must designate a word-aligned table readable
/// at `index * 0x18c`; the selected entry must contain a live object pointer
/// readable as a `u32` at `+0x860`. There are deliberately no bounds or null
/// checks, matching the original loads.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_mode_flag(index: i16) -> u32 {
    let object_slot = mode_state_object_table().offset(index as isize * MODE_STATE_RECORD_STRIDE);
    let object = (object_slot as *const *const u8).read();
    (object.add(MODE_STATE_FLAG_OFFSET) as *const u32).read() & 0x1f
}

/// indexed_mode_state_flag — original: `FUN_080df7f8` @ `0x080df7f8`
/// (28 bytes).
///
/// Verified call count: three unconditional `bl` sites (`0x080df70c`,
/// `0x080df794`, and `0x080df7bc`); no predicated calls. Raw ARM multiplies
/// the signed low halfword of `index` by 99, loads the object pointer from
/// [`MODE_STATE_OBJECT_TABLE`], then returns the low five bits of its word at
/// `+0x1e0`. The word's concrete meaning is not recovered, so the name records
/// its indexed mode-state flag role.
///
/// Deliberate deviations: the literal table pointer at `0x080df814` shares the
/// existing target-global seam; otherwise this directly preserves the ARM
/// loads, signed-halfword multiplication, and lack of bounds or null checks.
///
/// # Safety
///
/// [`MODE_STATE_OBJECT_TABLE`] must designate a word-aligned table readable
/// at `index * 0x18c`; the selected entry must contain a live object pointer
/// readable as a `u32` at `+0x1e0`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_mode_state_flag(index: i16) -> u32 {
    let object_slot = mode_state_object_table().offset(index as isize * MODE_STATE_RECORD_STRIDE);
    let object = (object_slot as *const *const u8).read();
    (object.add(MODE_STATE_STATE_FLAG_OFFSET) as *const u32).read() & 0x1f
}

/// Byte offset of the state-flag word in a selected object.
const MODE_STATE_STATE_FLAG_OFFSET: usize = 0x1e0;

/// indexed_mode_status — original: `FUN_080db5b4` @ `0x080db5b4`
/// (32 bytes: 28 bytes of code plus the table-pointer literal).
///
/// Verified call count: four unconditional `bl` sites (`0x08039a34`,
/// `0x080aa04c`, `0x080b62e4`, and `0x080cc544`); no predicated calls.
/// Raw ARM multiplies the signed low halfword of `index` by 99, loads the
/// selected object pointer from [`MODE_STATE_OBJECT_TABLE`], then returns
/// the low two bits of its word at `+0x400`.
///
/// Deliberate deviations: the table's literal at `0x080db5d0` is shared
/// through the existing target-global seam; otherwise this is a direct
/// translation with no bounds or null checks.
///
/// # Safety
///
/// [`MODE_STATE_OBJECT_TABLE`] must designate a word-aligned table readable
/// at `index * 0x18c`; the selected entry must contain a live object pointer
/// readable as a `u32` at `+0x400`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_mode_status(index: i16) -> u32 {
    let object_slot = mode_state_object_table().offset(index as isize * MODE_STATE_RECORD_STRIDE);
    let object = (object_slot as *const *const u8).read();
    (object.add(MODE_STATE_STATUS_OFFSET) as *const u32).read() & 3
}


/// indexed_mode_substate_code — original: `FUN_080dd2a0` @ `0x080dd2a0`
/// (40 bytes: 36 bytes of code plus a 4-byte literal).
///
/// Verified call count: six unconditional `bl` sites
/// (`0x080a61ac`, `0x080df660`, `0x080df688`, `0x080df69c`,
/// `0x080df6dc`, and `0x080df6f0`); no predicated calls. Raw ARM multiplies
/// the signed low halfword of `index` by 99, loads the object pointer from
/// [`MODE_STATE_OBJECT_TABLE`], calls `FUN_080e1cc8` to select one of eight
/// embedded substates, then returns the low three bits of that substate's
/// word at `+0x14`.
///
/// [`select_mode_substate`] preserves the original selector mapping. An
/// invalid selector makes the stock helper return null and the following
/// load fault; it remains outside this function's safety contract.
///
/// # Safety
///
/// [`MODE_STATE_OBJECT_TABLE`] must be valid for the signed index's record,
/// that record must hold a valid object pointer, and `selector` must be in
/// `0..=7`. The selected substate's word at `+0x14` must be aligned and
/// readable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_mode_substate_code(index: i16, selector: u32) -> u32 {
    let object_slot = mode_state_object_table().offset(index as isize * MODE_STATE_RECORD_STRIDE);
    let object = (object_slot as *const *const u8).read();
    let substate = select_mode_substate(object as *mut u8, selector);

    (substate.wrapping_add(MODE_STATE_SUBSTATE_CODE_OFFSET) as *const u32).read() & 7
}


/// indexed_mode_word_848_set — original: `FUN_080d98c4` @ `0x080d98c4`.
///
/// True extent: 32 bytes (28 instruction bytes and the table literal at
/// `0x080d98e0`), before the next function's push at `0x080d98e4`.
/// Verified incoming calls: one plain BL at `0x080adf64`, one BLNE at
/// `0x080adf70`; no outgoing BLs. Multiply the signed low halfword of the
/// index by 99 words, load the selected mode-state object, and overwrite
/// its word at `+0x848` with one. The word's concrete meaning is unknown.
///
/// Deliberate deviations: reuse the existing replaceable table seam for
/// the literal `0x08b2f648`. Host-only unaligned pointer loading accommodates
/// native pointers in records whose target byte stride remains `0x18c`;
/// target pointer loads and the stored word remain word-aligned.
///
/// # Safety
///
/// The table must contain a live object pointer at the signed index's
/// record, and that object must be writable and word-aligned at `+0x848`.
/// There are no bounds or null checks, matching the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_mode_word_848_set(index: i16) {
    let object_slot = mode_state_object_table().offset(index as isize * MODE_STATE_RECORD_STRIDE);
    #[cfg(target_pointer_width = "32")]
    let object = (object_slot as *const *mut u8).read();
    #[cfg(not(target_pointer_width = "32"))]
    let object = (object_slot as *const *mut u8).read_unaligned();
    (object.add(0x848) as *mut u32).write(1);
}

/// indexed_mode_word_804_set — original: `FUN_080c857c` @ `0x080c857c`.
///
/// True extent: 32 bytes (28 instruction bytes plus the table literal at
/// `0x080c8598`); the next function begins at `0x080c859c`.
/// Verified incoming calls: one plain BL at `0x080af668` and one BLNE at
/// `0x080adf1c`; zero outgoing plain or predicated BLs. Multiply the signed
/// low halfword index by 99 words, load its mode-state object pointer, and
/// overwrite the word at `+0x804` with one. Its concrete meaning is unknown.
///
/// Deliberate deviations: reuse the existing replaceable table seam for
/// literal `0x08b2f648`. Host-only unaligned native-pointer loads preserve
/// the target's `0x18c` record stride; target accesses remain word-aligned.
///
/// # Safety
///
/// The table must contain a live object pointer at the signed index's
/// record, and that object must be writable and word-aligned at `+0x804`.
/// No bounds or null checks, matching the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_mode_word_804_set(index: i16) {
    let object_slot = mode_state_object_table().offset(index as isize * MODE_STATE_RECORD_STRIDE);
    #[cfg(target_pointer_width = "32")]
    let object = (object_slot as *const *mut u8).read();
    #[cfg(not(target_pointer_width = "32"))]
    let object = (object_slot as *const *mut u8).read_unaligned();
    (object.add(0x804) as *mut u32).write(1);
}

/// indexed_mode_range — original: `FUN_080b64fc` @ `0x080b64fc`.
///
/// True extent: 72 bytes (68 instruction bytes and the table literal at
/// `0x080b6544`), ending at the next function's `0x080b6548` entry.
/// Verified incoming calls: two plain BLs at `0x080394e0` and `0x080d7f48`,
/// no predicated BLs; zero outgoing plain or predicated BLs.
/// Select the signed index's 0x18c-byte mode record. For selectors 0..=3,
/// write the record's base plus the object's range offset at
/// `0xa48 + selector * 0x14`, then its length at `0xa44 + selector * 0x14`.
/// Address addition wraps at 32 bits. Other selectors return -251 without
/// touching the output or dereferencing the object.
///
/// Deliberate deviations: reuse MODE_STATE_OBJECT_TABLE for 0x08b2f648.
/// Host records hold a native pointer followed by a u32 base (at +8 rather
/// than target +4); unaligned host pointer reads retain the 0x18c stride.
///
/// # Safety
///
/// The selected record must be readable even for invalid selectors. Valid
/// selectors require aligned readable object words and two writable output
/// words. Output may alias the object; the original store/load order is kept.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_mode_range(index: i16, selector: u32, output: *mut u32) -> i32 {
    let record = mode_state_object_table().offset(index as isize * MODE_STATE_RECORD_STRIDE);
    #[cfg(target_pointer_width = "32")]
    let object = (record as *const *const u8).read();
    #[cfg(not(target_pointer_width = "32"))]
    let object = (record as *const *const u8).read_unaligned();
    if selector > 3 {
        return -251;
    }
    let range = object.add(selector as usize * 0x14);
    let offset = (range.add(0xa48) as *const u32).read();
    let base = (record.add(core::mem::size_of::<*const u8>()) as *const u32).read();
    output.write(base.wrapping_add(offset));
    output.add(1).write((range.add(0xa44) as *const u32).read());
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::Mutex;

    static MODE_STATE_TABLE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn mode_range_signed_indices_selectors_wrapping_and_aliasing() {
        let _guard = MODE_STATE_TABLE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut table = ModeStateTable([0; MODE_STATE_RECORD_STRIDE as usize * 3]);
        let mut objects = [[0u32; 0xac0 / 4]; 3];
        unsafe {
            let previous = MODE_STATE_OBJECT_TABLE;
            for slot in 0..3 {
                install_object(&mut table, slot, objects[slot].as_ptr() as *const u8);
                (table.0.as_mut_ptr().add(slot * MODE_STATE_RECORD_STRIDE as usize
                    + core::mem::size_of::<*const u8>()) as *mut u32).write(0xffff_fff0 + slot as u32);
                for selector in 0..4 {
                    objects[slot][(0xa44 + selector * 0x14) / 4] = 0x100 * slot as u32 + selector as u32;
                    objects[slot][(0xa48 + selector * 0x14) / 4] = 0x20 + selector as u32;
                }
            }
            MODE_STATE_OBJECT_TABLE = table.0.as_ptr().add(MODE_STATE_RECORD_STRIDE as usize);
            for index in [-1i16, 0, 1] {
                for selector in 0..4u32 {
                    let mut output = [0xdead_beef; 4];
                    assert_eq!(indexed_mode_range(index, selector, output.as_mut_ptr().add(1)), 0);
                    assert_eq!(output, [0xdead_beef, 0x10 + (index + 1) as u32 + selector,
                        0x100 * (index + 1) as u32 + selector, 0xdead_beef]);
                }
            }
            // The first output store overwrites the length before it is read.
            let length = objects[1].as_mut_ptr().add(0xa44 / 4);
            assert_eq!(indexed_mode_range(0, 0, length), 0);
            assert_eq!([length.read(), length.add(1).read()], [0x11, 0x11]);
            // Invalid selectors accept a null object and never access output.
            install_object(&mut table, 1, core::ptr::null());
            for selector in [4, 0x8000_0000, u32::MAX] {
                let mut output = [0x1234_5678, 0xabcdef01];
                assert_eq!(indexed_mode_range(0, selector, output.as_mut_ptr()), -251);
                assert_eq!(output, [0x1234_5678, 0xabcdef01]);
                assert_eq!(indexed_mode_range(0, selector, core::ptr::null_mut()), -251);
            }
            MODE_STATE_OBJECT_TABLE = previous;
        }
    }

    #[repr(align(8))]
    struct ModeStateTable([u8; MODE_STATE_RECORD_STRIDE as usize * 3]);

    #[repr(align(4))]
    struct ModeStateObject([u8; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]);

    unsafe fn install_object(table: &mut ModeStateTable, index: usize, object: *const u8) {
        (table.0.as_mut_ptr().add(index * MODE_STATE_RECORD_STRIDE as usize) as *mut *const u8)
            .write_unaligned(object);
    }

    #[test]
    fn word_804_set_preserves_other_bytes_for_signed_indices_and_overwrites() {
        let _guard = MODE_STATE_TABLE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut table = ModeStateTable([0; MODE_STATE_RECORD_STRIDE as usize * 3]);
        let mut objects = [
            ModeStateObject([0xa5; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]),
            ModeStateObject([0xa5; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]),
            ModeStateObject([0xa5; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]),
        ];
        unsafe {
            for (slot, object) in objects.iter_mut().enumerate() {
                install_object(&mut table, slot, object.0.as_mut_ptr());
            }
            let previous = MODE_STATE_OBJECT_TABLE;
            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE)
                .write(table.0.as_ptr().add(MODE_STATE_RECORD_STRIDE as usize));
            for index in [-1i16, 0, 1] {
                for initial in [0u32, 1, 0xdead_beef, u32::MAX] {
                    let selected = (index + 1) as usize;
                    (objects[selected].0.as_mut_ptr().add(0x804) as *mut u32).write(initial);
                    let mut expected = objects.each_ref().map(|object| object.0);
                    expected[selected][0x804..0x808].copy_from_slice(&1u32.to_ne_bytes());
                    indexed_mode_word_804_set(index);
                    assert_eq!(objects.each_ref().map(|object| object.0), expected);
                    indexed_mode_word_804_set(index);
                    assert_eq!(objects.each_ref().map(|object| object.0), expected);
                }
            }
            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(previous);
        }
    }

    #[test]
    fn sets_only_selected_word_for_signed_indices_and_repeated_calls() {
        let _guard = MODE_STATE_TABLE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut table = ModeStateTable([0; MODE_STATE_RECORD_STRIDE as usize * 3]);
        let mut objects = [
            ModeStateObject([0xa5; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]),
            ModeStateObject([0xa5; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]),
            ModeStateObject([0xa5; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]),
        ];
        unsafe {
            for (slot, object) in objects.iter_mut().enumerate() {
                install_object(&mut table, slot, object.0.as_mut_ptr());
            }
            let previous = MODE_STATE_OBJECT_TABLE;
            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE)
                .write(table.0.as_ptr().add(MODE_STATE_RECORD_STRIDE as usize));
            for index in [-1i16, 0, 1] {
                for initial in [0u32, 1, 0xdead_beef, u32::MAX] {
                    let selected = (index + 1) as usize;
                    (objects[selected].0.as_mut_ptr().add(0x848) as *mut u32).write(initial);
                    let mut expected = objects.each_ref().map(|object| object.0);
                    expected[selected][0x848..0x84c].copy_from_slice(&1u32.to_ne_bytes());
                    indexed_mode_word_848_set(index);
                    assert_eq!(objects.each_ref().map(|object| object.0), expected);
                    indexed_mode_word_848_set(index);
                    assert_eq!(objects.each_ref().map(|object| object.0), expected);
                }
            }
            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(previous);
        }
    }

    #[test]
    fn indexes_records_at_arm_stride_and_masks_the_mode_word() {
        let _guard = MODE_STATE_TABLE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut table = ModeStateTable([0; MODE_STATE_RECORD_STRIDE as usize * 3]);
        let mut first = ModeStateObject([0; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]);
        let mut third = ModeStateObject([0; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]);

        unsafe {
            (first.0.as_mut_ptr().add(MODE_STATE_FLAG_OFFSET) as *mut u32).write(0xfeed_beff);
            (third.0.as_mut_ptr().add(MODE_STATE_FLAG_OFFSET) as *mut u32).write(0x89ab_caf5);
            install_object(&mut table, 0, first.0.as_ptr());
            install_object(&mut table, 2, third.0.as_ptr());
            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(table.0.as_ptr());

            assert_eq!(indexed_mode_flag(0), 0x1f);
            assert_eq!(indexed_mode_flag(2), 0x15);

            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(core::ptr::null());
        }
    }

    #[test]
    fn indexes_records_at_arm_stride_and_masks_the_state_flag_word() {
        let _guard = MODE_STATE_TABLE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut table = ModeStateTable([0; MODE_STATE_RECORD_STRIDE as usize * 3]);
        let mut first = ModeStateObject([0; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]);
        let mut third = ModeStateObject([0; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]);

        unsafe {
            (first.0.as_mut_ptr().add(MODE_STATE_STATE_FLAG_OFFSET) as *mut u32).write(0xfeed_beff);
            (third.0.as_mut_ptr().add(MODE_STATE_STATE_FLAG_OFFSET) as *mut u32).write(0x89ab_caf5);
            install_object(&mut table, 0, first.0.as_ptr());
            install_object(&mut table, 2, third.0.as_ptr());
            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(table.0.as_ptr());

            assert_eq!(indexed_mode_state_flag(0), 0x1f);
            assert_eq!(indexed_mode_state_flag(2), 0x15);

            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(core::ptr::null());
        }
    }

    #[test]
    fn indexes_records_at_arm_stride_and_masks_the_status_word() {
        let _guard = MODE_STATE_TABLE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut table = ModeStateTable([0; MODE_STATE_RECORD_STRIDE as usize * 3]);
        let mut first = ModeStateObject([0; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]);
        let mut third = ModeStateObject([0; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]);

        unsafe {
            (first.0.as_mut_ptr().add(MODE_STATE_STATUS_OFFSET) as *mut u32).write(0xfeed_beec);
            (third.0.as_mut_ptr().add(MODE_STATE_STATUS_OFFSET) as *mut u32).write(0x89ab_caf7);
            install_object(&mut table, 0, first.0.as_ptr());
            install_object(&mut table, 2, third.0.as_ptr());
            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(table.0.as_ptr());

            assert_eq!(indexed_mode_status(0), 0);
            assert_eq!(indexed_mode_status(2), 3);

            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(core::ptr::null());
        }
    }


    #[test]
    fn selects_all_mode_substate_offsets_and_rejects_invalid_selectors() {
        let mut object = [0u8; 0x231];
        let base = object.as_mut_ptr();
        let cases = [
            (0, 0x000),
            (1, 0x020),
            (2, 0x040),
            (3, 0x060),
            (4, 0x100),
            (5, 0x180),
            (6, 0x200),
            (7, 0x230),
        ];

        for (selector, offset) in cases {
            assert_eq!(select_mode_substate(base, selector), unsafe { base.add(offset) });
        }
        assert!(select_mode_substate(base, 8).is_null());
        assert!(select_mode_substate(base, u32::MAX).is_null());
    }
    #[test]
    fn selects_each_substate_and_masks_its_status_code() {
        let _guard = MODE_STATE_TABLE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut table = ModeStateTable([0; MODE_STATE_RECORD_STRIDE as usize * 3]);
        let mut object = ModeStateObject([0; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]);
        let substates = [
            (0, 0x000, 0xffff_fff8),
            (1, 0x020, 0x1234_5679),
            (2, 0x040, 0xfeed_beea),
            (3, 0x060, 0x89ab_cafb),
            (4, 0x100, 0xabcd_ef0c),
            (5, 0x180, 0x7654_321d),
            (6, 0x200, 0x1357_9b1e),
            (7, 0x230, 0x2468_acef),
        ];

        unsafe {
            for (selector, offset, code) in substates {
                (object.0.as_mut_ptr().add(offset + MODE_STATE_SUBSTATE_CODE_OFFSET) as *mut u32)
                    .write(code);
                assert_eq!(code & 7, selector);
            }
            install_object(&mut table, 1, object.0.as_ptr());
            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(table.0.as_ptr());

            for (selector, _, code) in substates {
                assert_eq!(indexed_mode_substate_code(1, selector), code & 7);
            }

            core::ptr::addr_of_mut!(MODE_STATE_OBJECT_TABLE).write(core::ptr::null());
        }
    }
}

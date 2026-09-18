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
/// The selector mapping from the unported `FUN_080e1cc8` is deliberately
/// inlined: selectors 0–3 select `selector * 0x20`, while selectors 4–7
/// select `0x100`, `0x180`, `0x200`, and `0x230`. An invalid selector makes
/// the stock helper return null and the following load fault; it remains
/// outside this function's safety contract.
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
    let substate = match selector {
        0..=3 => object.add(selector as usize * 0x20),
        4 => object.add(0x100),
        5 => object.add(0x180),
        6 => object.add(0x200),
        7 => object.add(0x230),
        _ => core::ptr::null(),
    };

    (substate.wrapping_add(MODE_STATE_SUBSTATE_CODE_OFFSET) as *const u32).read() & 7
}


#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::Mutex;

    static MODE_STATE_TABLE_LOCK: Mutex<()> = Mutex::new(());

    #[repr(align(8))]
    struct ModeStateTable([u8; MODE_STATE_RECORD_STRIDE as usize * 3]);

    #[repr(align(4))]
    struct ModeStateObject([u8; MODE_STATE_FLAG_OFFSET + core::mem::size_of::<u32>()]);

    unsafe fn install_object(table: &mut ModeStateTable, index: usize, object: *const u8) {
        (table.0.as_mut_ptr().add(index * MODE_STATE_RECORD_STRIDE as usize) as *mut *const u8)
            .write_unaligned(object);
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

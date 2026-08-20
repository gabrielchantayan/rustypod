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

/// Byte offset of the mode word in a selected object.
const MODE_STATE_FLAG_OFFSET: usize = 0x860;

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
}

//! Set calendar selection: FUN_08141290 at 0x08141290, 28 bytes.
//! Raw extent is [0x08141290,0x081412ac), before the next function's push.
//! Calls: one plain outgoing BL, zero predicated BLs, one tail B;
//! incoming references are one plain BL and one BLNE.
//!
//! Set the date and its nonzero-valid flag in the owner at view+0xec,
//! then invalidate the selected day through the existing retailOS helper.
//! The setter preserves r2, where the original saves the view pointer.
//! Deviations: use the C ABI rather than depending on caller-saved r2;
//! the two unported helpers remain calls to their verified ARM addresses.

type SetDate = unsafe extern "C" fn(*mut u32, u32);
type InvalidateSelection = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn owner_set_selected_date(owner: *mut u32, date: u32) {
    core::mem::transmute::<usize, SetDate>(0x081c_a470usize)(owner, date)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn owner_set_selected_date(_: *mut u32, _: u32) {
    panic!("calendar selection requires retailOS setter 0x081ca470")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn invalidate_selected_day(view: *mut u32) {
    core::mem::transmute::<usize, InvalidateSelection>(0x0814_0c20usize)(view)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn invalidate_selected_day(_: *mut u32) {
    panic!("calendar selection requires retailOS invalidation 0x08140c20")
}

/// Change the selected date, then invalidate its calendar cell.
///
/// # Safety
/// `view` must be a live retailOS calendar view with a valid writable owner
/// pointer at word offset 0xec/4. The owner must be writable through +0xec;
/// a nonzero date must be valid for the retailOS calendar helpers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn calendar_set_selected_date(view: *mut u32, date: u32) {
    set_selected_date_with(view, date, owner_set_selected_date, invalidate_selected_day);
}

unsafe fn set_selected_date_with(view: *mut u32, date: u32,
    set_date: SetDate, invalidate: InvalidateSelection,
) {
    let owner = view.add(0xec / 4).read() as usize as *mut u32;
    set_date(owner, date);
    invalidate(view);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Models the raw setter's word store and byte store, not a host-width field.
    unsafe extern "C" fn set_date(owner: *mut u32, date: u32) {
        owner.add(0xe8 / 4).write(date);
        owner.cast::<u8>().add(0xec).write(u8::from(date != 0));
    }

    // Model the selection gate: retain the last invalidated date when cleared.
    unsafe extern "C" fn invalidate(view: *mut u32) {
        let owner = view.add(0xec / 4).read() as usize as *mut u32;
        if !owner.is_null() && owner.cast::<u8>().add(0xec).read() != 0 {
            view.add(0xf0 / 4).write(owner.add(0xe8 / 4).read());
        }
    }

    #[test]
    fn selection_transitions_update_before_invalidation_and_clear_only_valid_byte() {
        unsafe {
            let Some(slab) = crate::testing::try_map_u32_slab(
                crate::testing::hints::CALENDAR_SET_SELECTED_DATE, 0x1000,
            ) else { return };
            let view = slab.cast::<u32>();
            let owner = slab.add(0x400).cast::<u32>();
            view.add(0xec / 4).write(owner as usize as u32);
            owner.add(0xe4 / 4).write(0x12345678);
            owner.add(0xec / 4).write(0xaabbccfe);
            view.add(0xf0 / 4).write(99);
            let mut last_invalidated = 99;
            for date in [1, 0, 0x80000000, u32::MAX, 0, 17] {
                set_selected_date_with(view, date, set_date, invalidate);
                if date != 0 { last_invalidated = date; }
                assert_eq!(owner.add(0xe8 / 4).read(), date);
                assert_eq!(owner.add(0xec / 4).read(), 0xaabbcc00 | u32::from(date != 0));
                assert_eq!(owner.add(0xe4 / 4).read(), 0x12345678);
                assert_eq!(view.add(0xf0 / 4).read(), last_invalidated);
                assert_eq!(view.add(0xec / 4).read(), owner as usize as u32);
            }
        }
    }
}

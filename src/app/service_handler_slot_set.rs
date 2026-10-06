//! Sets a service-handler word in the application's indexed table.
//!
//! Original: `FUN_08193ed4` @ `0x08193ed4`, true extent
//! `[0x08193ed4, 0x08193ee8)` (20 bytes; next function starts with CMP).
//! Raw-image decoding finds two plain incoming BLs (0x08165744,
//! 0x08165858), zero predicated incoming BLs. Body: zero plain BLs,
//! one signed BLGE to the existing `heap_panic` @ 0x08030f44.
//!
//! Reject signed indices >=13, then store the full handler word at
//! `table + 0x64 + slot*8`. The constructor installs handlers for slots
//! 0..12 using this entry. Negative indices deliberately remain accepted.
//! No behavioral deviations; u32 word indexing preserves the firmware
//! layout on hosts with wider pointers. The fatal path may gain a frame.

/// # Safety
/// For `slot < 13`, `table` must be aligned and the word at byte offset
/// `0x64 + slot*8` must lie within its writable allocation. Negative slots
/// are allowed, so the caller may need storage preceding `table`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_slot_set(table: *mut u32, slot: i32, handler: u32) {
    if slot >= 13 {
        crate::heap::veneers::heap_panic();
    }
    table.offset(25 + slot as isize * 2).write(handler);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use self::std::string::ToString;
    use super::service_handler_slot_set;

    #[test]
    fn selected_word_only_changes_for_all_slots_and_full_width_handlers() {
        for slot in 0..13 {
            for handler in [0, 1, 0x8000_0000, u32::MAX] {
                let mut words = [0xa5a5_5a5au32; 52];
                let mut expected = words;
                expected[25 + slot as usize * 2] = handler;
                unsafe { service_handler_slot_set(words.as_mut_ptr(), slot, handler); }
                assert_eq!(words, expected);
            }
        }
    }

    #[test]
    fn negative_slots_use_signed_addressing() {
        for slot in [-1, -12, -13, -20] {
            let mut words = [0x1234_5678u32; 80];
            let mut expected = words;
            expected[(40 + 25 + slot * 2) as usize] = 0xfedc_ba98;
            unsafe { service_handler_slot_set(words.as_mut_ptr().add(40), slot, 0xfedc_ba98); }
            assert_eq!(words, expected);
        }
    }

    unsafe extern "C" fn invalid_slot() -> ! {
        let slot = std::env::var("RUSTYPOD_SERVICE_SLOT_INVALID").unwrap().parse().unwrap();
        service_handler_slot_set(core::ptr::null_mut(), slot, 0);
        std::process::exit(5);
    }

    #[test]
    fn upper_boundary_and_maximum_are_fatal_before_memory_access() {
        for slot in [13, i32::MAX] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "app::service_handler_slot_set::tests::fatal_child"])
                .env("RUSTYPOD_SERVICE_SLOT_INVALID", slot.to_string())
                .status().unwrap();
            assert!(status.success(), "slot {slot}: {status}");
        }
    }

    #[test]
    fn fatal_child() {
        if std::env::var_os("RUSTYPOD_SERVICE_SLOT_INVALID").is_none() { return; }
        crate::heap::veneers::tests::assert_heap_panic_entry_fatal_path(
            "RUSTYPOD_SERVICE_SLOT_INVALID",
            "app::service_handler_slot_set::tests::fatal_child",
            invalid_slot,
        );
    }
}

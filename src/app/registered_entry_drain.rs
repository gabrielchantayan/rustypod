//! Registered-entry ring drain — `FUN_082938f8` @ `0x082938f8`.
//!
//! True extent: 176 bytes (172 code + table literal), ending at the independent
//! entry `0x082939a8`. Raw A32 scan: one plain and one predicated inbound BL;
//! three plain outbound BLs, no predicated outbound BLs.
//! Advance the four-slot cursor with unsigned wrapping arithmetic. If the next
//! buffer is absent, restore the old cursor and return zero. Otherwise detach
//! that buffer, visit its 12-byte descriptors until the retail operation returns
//! zero, then post the keyed registration mailbox and return one, even for an
//! empty buffer. Counts are retained. The retail operation at 0x08107b20 is
//! exactly `mov r0,#1; bx lr`; its domain identity is deliberately not claimed.
//! Deviation: host execution injects retail effects; target retains the typed
//! address call. Word indices preserve the target's four-byte field spacing.

#[inline(always)]
unsafe fn drain_with(
    controller: *mut u32,
    key: u32,
    mut visit: impl FnMut(u32, u32, u32, u32) -> i32,
    mut notify: impl FnMut(*mut u32, u32),
) -> i32 {
    let old = controller.add(12).read();
    let advanced = old.wrapping_add(1);
    let next = if advanced >= 4 { 0 } else { advanced };
    controller.add(12).write(next);
    let slot = controller.add(3 + next as usize);
    let mut descriptor = slot.read();
    if descriptor == 0 {
        controller.add(12).write(old);
        return 0;
    }
    slot.write(0);
    let count = controller.add(7 + next as usize).read();
    let mut index = 0;
    while index < count {
        let context = controller.add(13).read();
        if visit(context, key, descriptor, 10) == 0 { break; }
        descriptor = descriptor.wrapping_add(12);
        index += 1;
    }
    notify(controller, key);
    1
}

/// Drain the next occupied ring buffer and notify the keyed registration.
///
/// # Safety
/// `controller` must provide fourteen aligned target words, valid descriptor
/// buffers, a valid channel context, and a key present in the retail slot table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registered_entry_drain(controller: *mut u8, key: u32) -> i32 {
    #[cfg(target_os = "none")]
    {
        drain_with(controller.cast(), key, |context, key, descriptor, mode| {
            let operation: unsafe extern "C" fn(u32, u32, u32, u32) -> i32 =
                core::mem::transmute(0x0810_7b20usize);
            operation(context, key, descriptor, mode)
        }, |controller, key| {
            let index = crate::app::four_slot_key_index::four_slot_key_index(controller.cast(), key);
            let cell = (0x089d_04c4u32).wrapping_add((index as u32).wrapping_mul(24)).wrapping_add(4);
            let mailbox = (cell as *const u32).read();
            crate::kernel::kobj::mailbox_slot_post(mailbox as *mut *mut crate::kernel::kobj::Mailbox);
        })
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (controller, key);
        panic!("registered_entry_drain requires retailOS addresses on host");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_next_slot_restores_cursor_without_searching_later_slots() {
        for old in [0, 1, 2, 3, 4, u32::MAX] {
            let mut words = [0u32; 14];
            words[12] = old;
            let before = words;
            unsafe {
                assert_eq!(drain_with(words.as_mut_ptr(), 0x83,
                    |_, _, _, _| panic!("absent buffer visited"),
                    |_, _| panic!("absent buffer notified")), 0);
            }
            assert_eq!(words, before);
        }
    }

    #[test]
    fn detached_buffer_walks_descriptors_and_notifies_even_when_empty_or_stopped() {
        for (old, count, stop, expected) in [(3, 0, 9, 0), (0, 3, 9, 3), (2, 4, 1, 2), (u32::MAX, 2, 9, 2)] {
            let next = if old == u32::MAX || old == 3 { 0 } else { old + 1 };
            let mut words = [0u32; 14];
            words[12] = old;
            words[13] = 0x1234;
            words[3 + next as usize] = 0xffff_fff8;
            words[7 + next as usize] = count;
            let ptr = words.as_mut_ptr();
            let mut calls = 0u32;
            let mut notified = false;
            unsafe {
                assert_eq!(drain_with(ptr, 0x83, |context, key, descriptor, mode| {
                    assert_eq!((context, key, mode), (0x1234, 0x83, 10));
                    assert_eq!(descriptor, 0xffff_fff8u32.wrapping_add(calls * 12));
                    assert_eq!(ptr.add(3 + next as usize).read(), 0);
                    assert_eq!(ptr.add(12).read(), next);
                    let result = (calls != stop) as i32;
                    calls += 1;
                    result
                }, |controller, key| {
                    assert_eq!((controller, key), (ptr, 0x83));
                    notified = true;
                }), 1);
            }
            assert_eq!(calls, expected);
            assert!(notified);
            assert_eq!(words[7 + next as usize], count);
            assert_eq!(words[12], next);
        }
    }
}

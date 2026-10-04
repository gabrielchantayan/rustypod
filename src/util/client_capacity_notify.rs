//! `client_capacity_notify` — `FUN_081fc230` @ `0x081fc230`.
//! True extent: 104 bytes, ending at the next prologue at `0x081fc298`.
//! Raw words verify three outgoing plain BLs, zero predicated BLs; two
//! inbound plain BLs (erase and return-region).
//!
//! Requires flag 1 and signed produced (+0x18) <= capacity_end (+0x50).
//! If flag 0x100000 is absent, sends parent (+4) event 7 with this client,
//! then reloads and ORs the flag word (+0x44). Returns 1 for an eligible
//! client, including already-notified clients; otherwise returns 0.
//!
//! Deliberate deviations: omit the unused r2 argument to the flag helper;
//! the unported parent notifier is called at its verified resident address
//! through BLX rather than BL. Host execution rejects that resident call;
//! behavioral tests exercise the same algorithm with a synchronous callback.

use crate::util::state_flags::state_flags_contain;

#[inline(always)]
unsafe fn word(client: *mut u8, offset: usize) -> u32 {
    (client.add(offset) as *const u32).read_volatile()
}

#[inline(always)]
unsafe fn capacity_notify_with(client: *mut u8, notify: impl FnOnce(u32, u32, *mut u8)) -> u32 {
    if state_flags_contain(client, 1) == 0
        || (word(client, 0x18) as i32) > (word(client, 0x50) as i32)
    {
        return 0;
    }
    if state_flags_contain(client, 0x100000) == 0 {
        notify(word(client, 4), 7, client);
        let flags = client.add(0x44) as *mut u32;
        flags.write_volatile(flags.read_volatile() | 0x100000);
    }
    1
}

/// # Safety
/// `client` must provide aligned readable words through +0x50 and a writable
/// flag word at +0x44. Its parent must satisfy the resident event-queue ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn client_capacity_notify(client: *mut u8) -> u32 {
    capacity_notify_with(client, |parent, event, client| {
        #[cfg(target_os = "none")]
        {
            let notify: unsafe extern "C" fn(u32, u32, *mut u8) -> u32 =
                core::mem::transmute(0x0818_a41cusize);
            notify(parent, event, client);
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (parent, event, client);
            panic!("resident parent event notifier unavailable on host");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_boundaries_and_missing_enable_flag() {
        for flags in [0, 0x100000, 1, 0x100001] {
            for produced in [i32::MIN, -1, 0, 1, i32::MAX] {
                for capacity in [i32::MIN, -1, 0, 1, i32::MAX] {
                    let mut client = [0u32; 21];
                    client[1] = 0x12345678;
                    client[6] = produced as u32;
                    client[17] = flags;
                    client[20] = capacity as u32;
                    let pointer = client.as_mut_ptr().cast();
                    let eligible = flags & 1 != 0 && produced <= capacity;
                    let mut called = false;
                    let result = unsafe { capacity_notify_with(pointer, |parent, event, source| {
                        assert_eq!((parent, event, source), (0x12345678, 7, pointer));
                        assert_eq!(word(source, 0x44), flags);
                        called = true;
                    }) };
                    assert_eq!(result, u32::from(eligible));
                    assert_eq!(called, eligible && flags & 0x100000 == 0);
                    assert_eq!(client[17], flags | if eligible { 0x100000 } else { 0 });
                }
            }
        }
    }

    #[test]
    fn notification_precedes_flag_and_preserves_callback_changes() {
        let mut client = [0u32; 21];
        client[17] = 1;
        let pointer = client.as_mut_ptr().cast();
        unsafe {
            assert_eq!(capacity_notify_with(pointer, |_, _, source| {
                assert_eq!(word(source, 0x44), 1);
                (source.add(0x44) as *mut u32).write_volatile(0x80000000);
            }), 1);
            assert_eq!(client[17], 0x80100000);
            // The callback cleared enable: even the notification flag cannot
            // bypass the first gate.
            assert_eq!(capacity_notify_with(pointer, |_, _, _| panic!("ineligible")), 0);
            client[17] |= 1;
            assert_eq!(client_capacity_notify(pointer), 1);
            assert_eq!(client[17], 0x80100001);
        }
    }
}

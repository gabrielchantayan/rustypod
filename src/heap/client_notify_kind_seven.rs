//! Clears the client's outstanding limit and sends its current count as kind 7.
//!
//! `client_notify_kind_seven` — retailOS `FUN_081fc4f4` @ **0x081fc4f4**.
//! True extent **20 bytes**, `0x081fc4f4..0x081fc508`; the next raw word is
//! the independent `push {r4, lr}` at 0x081fc508. Words:
//! `e3a01000 e5801050 e590201c e3a01007 eafffeac`.
//! There are **two inbound plain BLs** (0x082077fc, 0x082078f4), **zero
//! predicated BLs**, and **zero outbound BLs**. The final B targets 0x081fbfbc,
//! which allocates a 16-byte event, constructs it with kind and payload, and
//! dispatches it through the client's virtual event sink unless flag 0x80000
//! suppresses dispatch. No stronger meaning is assigned to kind 7.
//!
//! Algorithm: write zero to target word 20 (+0x50), snapshot target word 7
//! (+0x1c), and notify with kind 7 and that snapshot. Deliberate deviation:
//! the unported helper is invoked through its resident address on target;
//! host tests replace that boundary. Rust does not reproduce Ghidra's false
//! four-argument signature or inline the helper's unrelated shared blocks.
//! Volatile aligned accesses retain the retail clear-before-load ordering.
//! Host suite and standalone production-entry smoke pass; ARM release builds.
//! `match.py` reports the expected structural diff: LLVM frame setup/teardown
//! and a literal-loaded BX replace the direct tail B, with the same stores,
//! payload load, kind 7, and destination. No device execution was performed.

pub type ClientKindNotification = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_notification(_client: *mut u8, _kind: u32, _count: u32) {
    panic!("client kind notification requires a resident implementation")
}

#[cfg(not(target_os = "none"))]
pub static mut NOTIFY: ClientKindNotification = missing_notification;

/// `client` must be word-aligned and writable through target offset +0x50.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn client_notify_kind_seven(client: *mut u8) {
    let words = client.cast::<u32>();
    core::ptr::write_volatile(words.add(20), 0);
    let count = core::ptr::read_volatile(words.add(7));
    #[cfg(target_os = "none")]
    let notify: ClientKindNotification = core::mem::transmute(0x081f_bfbc_usize);
    #[cfg(not(target_os = "none"))]
    let notify = core::ptr::read_volatile(core::ptr::addr_of!(NOTIFY));
    notify(client, 7, count);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn consume(client: *mut u8, kind: u32, count: u32) {
        let words = client.cast::<u32>();
        assert_eq!(words.add(20).read(), 0, "clear must precede dispatch");
        assert_eq!(kind, 7);
        assert_eq!(count, words.add(7).read());
        // A consumer is allowed to change the payload field during dispatch.
        words.add(7).write(count.wrapping_add(1));
    }

    struct Reset(ClientKindNotification);
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { NOTIFY = self.0; } }
    }

    #[test]
    fn clears_only_limit_before_dispatch_even_for_zero_and_maximum_counts() {
        let _guard = LOCK.lock();
        unsafe {
            let _reset = Reset(NOTIFY);
            NOTIFY = consume;
            for count in [0, 1, 0x8000_0000, u32::MAX] {
                for limit in [0, u32::MAX] {
                    let mut client = [0xa5a5_5a5a_u32; 24];
                    client[7] = count;
                    client[20] = limit;
                    let mut expected = client;
                    expected[7] = count.wrapping_add(1);
                    expected[20] = 0;
                    client_notify_kind_seven(client.as_mut_ptr().cast());
                    assert_eq!(client, expected, "neighbouring target words must survive");
                }
            }
        }
    }
}

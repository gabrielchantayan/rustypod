//! Request an empty lingo-8 command-1 packet.
//!
//! Original: `FUN_081e2d98` at **0x081e2d98**. True extent is **152 bytes**:
//! 148 instruction bytes ending at 0x081e2e28, then the 2500-ms literal at
//! 0x081e2e2c; the next function starts at 0x081e2e30. Raw ARM decoding
//! verifies **4 plain BLs, zero predicated BLs**, and two inbound plain BLs.
//!
//! With a pending owner and reply_progress[0] <= 3, create an empty lingo-8
//! command-1 packet and complete it with state zero and a 2500-ms delay.
//! Return 28 on creation failure, the completion status otherwise, or 11
//! when no packet is attempted. Progress above three skips creation, clears
//! the callback registry without resetting state fields, and broadcasts
//! (8, 0, 13, 4). Reload progress after creation/completion before deciding
//! whether to clear and broadcast.
//!
//! Deliberate deviations: the completion helper's unused fourth argument
//! is zero rather than residual r3. All callees use existing Rust ports;
//! no new seam or firmware global representation is introduced.

use core::ptr;

use super::event_hub::event_hub_broadcast;
use super::iap_packet::iap_packet_create;
use super::iap_packet_completion_schedule::complete_iap_packet_and_schedule_event;
use super::request_callback_state_reset::{request_callback_state_reset, RequestCallbackState};

/// # Safety
/// `state` must be a valid writable callback state; its nonzero pending
/// payload word must identify a valid packet owner in the target ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iap_command_1_request")]
pub unsafe extern "C" fn iap_command_1_request(state: *mut RequestCallbackState) -> u32 {
    let owner = ptr::read_volatile(ptr::addr_of!((*state).pending_request_payload));
    let mut status = 11;
    if owner != 0 {
        if ptr::read_volatile(ptr::addr_of!((*state).reply_progress[0])) > 3 {
            request_callback_state_reset(state, 0, 0);
            event_hub_broadcast(8, 0, 13, 4);
            return status;
        }
        let packet = iap_packet_create(owner as usize as *mut u8, ptr::null_mut(), 8, 1, ptr::null(), 0);
        status = if packet.is_null() {
            28
        } else {
            complete_iap_packet_and_schedule_event(packet, 0, 2500, 0)
        };
    }
    if ptr::read_volatile(ptr::addr_of!((*state).reply_progress[0])) > 3 {
        request_callback_state_reset(state, 0, 0);
        event_hub_broadcast(8, 0, 13, 4);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_owner_preserves_state_through_retry_three() {
        for retry in 0..=3 {
            let mut state: RequestCallbackState = unsafe { core::mem::zeroed() };
            state.pending_request = 0x7fff_ffff;
            state.reply_progress = [retry, 0xff, 0xff, 0xff];
            assert_eq!(unsafe { iap_command_1_request(&mut state) }, 11);
            assert_eq!(state.pending_request, 0x7fff_ffff);
            assert_eq!(state.pending_request_payload, 0);
            assert_eq!(state.reply_progress, [retry, 0xff, 0xff, 0xff]);
        }
    }
    #[test]
    fn exhausted_retries_skip_even_an_invalid_owner_and_preserve_state() {
        use super::super::event_hub::{EVENT_HUB_GUARD, EVENT_HUB_INSTANCE};
        let _registry_guard = super::super::request_callback_state_reset::tests::TEST_LOCK.lock();
        let _hub_guard = super::super::event_hub::tests::EVENT_HUB_LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            let saved_guard = ptr::addr_of!(EVENT_HUB_GUARD).read_volatile();
            let saved_instance = ptr::addr_of!(EVENT_HUB_INSTANCE).read_volatile();
            // Refused ADS acquire skips singleton allocation; default dispatch
            // does not dereference the null instance.
            ptr::addr_of_mut!(EVENT_HUB_GUARD).write_volatile(2);
            ptr::addr_of_mut!(EVENT_HUB_INSTANCE).write_volatile(ptr::null_mut());
            for owner in [0, 1] {
                for retry in [4, 255] {
                    let mut state: RequestCallbackState = core::mem::zeroed();
                    state.pending_request = 42;
                    state.pending_request_payload = owner;
                    state.reply_progress = [retry, 1, 2, 3];
                    assert_eq!(iap_command_1_request(&mut state), 11);
                    assert_eq!(state.pending_request, 42);
                    assert_eq!(state.pending_request_payload, owner);
                    assert_eq!(state.reply_progress, [retry, 1, 2, 3]);
                }
            }
            ptr::addr_of_mut!(EVENT_HUB_GUARD).write_volatile(saved_guard);
            ptr::addr_of_mut!(EVENT_HUB_INSTANCE).write_volatile(saved_instance);
        }
    }

}

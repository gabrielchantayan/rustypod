//! Complete a pending iAP packet from a request callback state.
//!
//! `request_callback_state_complete_iap_packet` — original: `FUN_081e2e30`
//! @ **0x081e2e30**. Raw `osos.dec` words establish the complete **152-byte**
//! extent: 148 instruction bytes through `pop {r2-r6,pc}` at 0x081e2ec0,
//! followed by the 0x00000bb8 literal; the next independently linked function
//! starts at 0x081e2ec8. The body has **4 plain unconditional `bl` calls**
//! (0x081e2e6c, 0x081e2e84, 0x081e2ea4, 0x081e2eb8) and **zero predicated
//! `bl` calls**. This corrects Ghidra's three-call result.
//!
//! Algorithm: when `pending_request_payload` is present and reply progress is
//! below four, allocate an empty lingo-8 command-4 packet, then complete it
//! with state zero and a 3000-ms delay. Allocation failure returns 28; other
//! completion failures propagate. Once progress reaches four, or with no
//! pending payload, reset the callback registry and broadcast event
//! `(8, 0, 13, 4)`. Otherwise return the default status 11.
//!
//! # Deliberate deviations
//!
//! None. The packet factory, completion scheduling, callback reset, and event
//! broadcast are already ported and called directly.

use core::ptr;

use super::event_hub::event_hub_broadcast;
use super::iap_packet::iap_packet_create;
use super::iap_packet_completion_schedule::complete_iap_packet_and_schedule_event;
use super::request_callback_state_reset::{request_callback_state_reset, RequestCallbackState};

const DEFAULT_STATUS: u32 = 11;
const PACKET_CREATE_FAILURE_STATUS: u32 = 28;
const REPLY_PROGRESS_LIMIT: u8 = 4;
const IAP_LINGO: u8 = 8;
const IAP_COMMAND: u16 = 4;
const COMPLETION_DELAY_MS: u32 = 3000;
const EVENT_KIND: u32 = 8;
const EVENT_PAYLOAD: usize = 13;
const EVENT_PAYLOAD_LEN: u32 = 4;

/// Completes the pending empty iAP packet when reply progress permits it.
///
/// Original: `FUN_081e2e30` at 0x081e2e30. `state` must name a valid
/// [`RequestCallbackState`]; a non-null pending payload is passed as the
/// packet owner exactly as in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.request_callback_state_complete_iap_packet")]
pub unsafe extern "C" fn request_callback_state_complete_iap_packet(
    state: *mut RequestCallbackState,
) -> u32 {
    let pending_payload = ptr::read_volatile(ptr::addr_of!((*state).pending_request_payload));
    let mut status = DEFAULT_STATUS;

    if pending_payload != 0 {
        if ptr::read_volatile(ptr::addr_of!((*state).reply_progress[2])) < REPLY_PROGRESS_LIMIT {
            let packet = iap_packet_create(
                pending_payload as *mut u8,
                ptr::null_mut(),
                IAP_LINGO,
                IAP_COMMAND,
                ptr::null(),
                0,
            );
            status = if packet.is_null() {
                PACKET_CREATE_FAILURE_STATUS
            } else {
                complete_iap_packet_and_schedule_event(packet, 0, COMPLETION_DELAY_MS, IAP_COMMAND as u32)
            };
        }
    }

    if ptr::read_volatile(ptr::addr_of!((*state).reply_progress[2])) >= REPLY_PROGRESS_LIMIT {
        request_callback_state_reset(state, 0, 0);
        event_hub_broadcast(EVENT_KIND, 0, EVENT_PAYLOAD, EVENT_PAYLOAD_LEN);
    }

    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_payload_returns_default_status_before_progress_limit() {
        let mut state: RequestCallbackState = unsafe { core::mem::zeroed() };
        state.pending_request = 0;
        state.pending_request_payload = 0;
        state.reply_progress = [0, 0, 0, 0];
        assert_eq!(unsafe { request_callback_state_complete_iap_packet(&mut state) }, DEFAULT_STATUS);
    }

    #[test]
    fn absent_payload_does_not_read_unrelated_reply_bytes() {
        let mut state: RequestCallbackState = unsafe { core::mem::zeroed() };
        state.pending_request = 0;
        state.pending_request_payload = 0;
        state.reply_progress = [u8::MAX, u8::MAX, 3, u8::MAX];
        assert_eq!(unsafe { request_callback_state_complete_iap_packet(&mut state) }, DEFAULT_STATUS);
    }
}

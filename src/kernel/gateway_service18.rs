//! Raw mask-ROM service-18 gateway request wrapper.
//!
//! `thunk_EXT_FUN_220041fc` is the 8-byte ADS literal veneer at load address
//! `0x08037f20`: raw words are `e51ff004` (`ldr pc, [pc, #-4]`) and
//! `220041fc`. The boot relocator copies `0x08000000..0x0800aed8` to IRAM, so
//! its target `0x220041fc` mirrors the 52-byte body at `0x080041fc` (ending
//! immediately before the sibling service-19 body at `0x08004230`).
//!
//! The body reserves seven words, then passes the six-word subrecord at
//! `sp + 4` to the foreign gateway dispatcher:
//! `{ service = 18, _, arg3, &subrecord, arg2, input }`. The input word is
//! stored first at the subrecord's last word (`sp + 24`); the raw body then
//! clobbers r1 to compute the subrecord's own address, so the caller's r1
//! argument is never forwarded. Remaining store order is `service,
//! &subrecord, arg2, arg3`. After dispatch it reloads and returns that last
//! word, so the dispatcher may rewrite the input word and the caller
//! observes the rewritten value. Subrecord word 1 and frame word 0 are
//! deliberately uninitialized exactly as in the raw ARM body.
//!
//! Every ARM B/BL immediate in `osos.dec` was decoded: the veneer has five
//! direct call sites — unconditional `bl` at `0x08084c0c`, `0x080c9c64`,
//! `0x08393684`, and `0x08393828`, plus one predicated `blne` at
//! `0x080e1878` — with no tail branches. No image word contains the veneer
//! or mirror address; only the veneer literal contains `0x220041fc`. The
//! callers hand over `(object, 250 | 2000 | mem | r7, 0, small_const)`
//! tuples, but the RTXC operation represented by selector 18 is not
//! recovered, so this module names the verified wire protocol rather than
//! inventing it.
//!
//! # Deliberate deviation
//!
//! The raw body calls the foreign `0x08003660` literal veneer. This port uses
//! its established [`message_dispatch_veneer`] seam, preserving the writable
//! request ABI while letting target integration bind the unavailable service
//! dispatcher and host tests inspect it.

use core::mem::MaybeUninit;

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// osos load address of `thunk_EXT_FUN_220041fc`.
pub const SERVICE18_THUNK: u32 = 0x0803_7f20;
/// IRAM target literal held by [`SERVICE18_THUNK`].
pub const SERVICE18_ROM_ENTRY: u32 = 0x2200_41fc;
/// The target body's byte-identical osos mirror.
pub const SERVICE18_MIRROR_ENTRY: u32 = 0x0800_41fc;

/// Gateway selector written at the start of the dispatch subrecord.
pub const GATEWAY_SERVICE_18: u32 = 18;

const FRAME_WORDS: usize = 7;
const REQUEST_START: usize = 1;
const SERVICE_WORD: usize = 0;
const ARG3_WORD: usize = 2;
const SELF_PTR_WORD: usize = 3;
const ARG2_WORD: usize = 4;
const INPUT_WORD: usize = 5;

/// gateway_service18_request — original: `thunk_EXT_FUN_220041fc` @
/// `0x08037f20` (8-byte veneer) → mirrored body `0x080041fc` (52 bytes; five
/// direct call sites, four unconditional `bl` and one `blne`).
///
/// Builds `{18, _, arg3, &record, arg2, input}` in the original seven-word
/// frame, calls the RTXC gateway dispatcher, and returns the post-dispatch
/// value of the input word. `r1_clobbered` mirrors the raw ABI: the body
/// overwrites r1 with the subrecord address before storing anything, so the
/// caller's second argument never reaches the dispatcher. The service's
/// higher-level identity is deliberately unknown; every argument is passed
/// without a NULL, sentinel, or range guard, matching every caller.
///
/// # Safety
///
/// The target dispatcher interprets the selector-specific writable frame. On
/// device it must be installed through `message_dispatch_veneer`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_service18_request(
    input: u32,
    r1_clobbered: u32,
    arg2: u32,
    arg3: u32,
) -> u32 {
    let mut frame = [MaybeUninit::<u32>::uninit(); FRAME_WORDS];
    let words = frame.as_mut_ptr().cast::<u32>();
    let request = words.add(REQUEST_START);

    // Exact raw-ARM store order: input at sp+24, service at sp+4, then
    // &subrecord, arg2, arg3 at sp+16, sp+20, sp+12.
    request.add(INPUT_WORD).write(input);
    request.add(SERVICE_WORD).write(GATEWAY_SERVICE_18);
    request.add(SELF_PTR_WORD).write(request as u32);
    request.add(ARG2_WORD).write(arg2);
    request.add(ARG3_WORD).write(arg3);
    let _ = r1_clobbered;
    message_dispatch_veneer(request);
    request.add(INPUT_WORD).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use parking_lot::MutexGuard;
    use std::vec::Vec;

    static mut OBSERVED: Vec<[u32; 6]> = Vec::new();
    static mut OUTPUT_TO_WRITE: u32 = 0;

    struct Recorder {
        _lock: MutexGuard<'static, ()>,
        saved: MessageDispatchVeneerOps,
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_VENEER_OPS = self.saved };
        }
    }

    unsafe extern "C" fn recording_dispatch(request: *mut u32) {
        OBSERVED.push([
            request.add(SERVICE_WORD).read(),
            request.add(ARG2_WORD).read(),
            request.add(ARG3_WORD).read(),
            request.add(INPUT_WORD).read(),
            request.add(SELF_PTR_WORD).read(),
            request as u32,
        ]);
        request.add(INPUT_WORD).write(OUTPUT_TO_WRITE);
    }

    fn install(output: u32) -> Recorder {
        let lock = DISPATCH_OPS_LOCK.lock();
        let saved = unsafe { MESSAGE_DISPATCH_VENEER_OPS };
        unsafe {
            OBSERVED = Vec::new();
            OUTPUT_TO_WRITE = output;
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps {
                dispatch: recording_dispatch,
            };
        }
        Recorder { _lock: lock, saved }
    }

    #[test]
    fn posts_service18_with_self_pointer_and_all_three_argument_words() {
        let _recorder = install(0);
        unsafe { gateway_service18_request(0xdecafbad, 250, 0, 0x43) };
        unsafe {
            let observed = OBSERVED.as_slice();
            assert_eq!(observed.len(), 1);
            let record = observed[0];
            assert_eq!(
                &record[..4],
                &[GATEWAY_SERVICE_18, 0, 0x43, 0xdecafbad],
                "the dispatcher receives [18, arg2, arg3, input] in raw layout"
            );
            assert_eq!(
                record[4], record[5],
                "subrecord word 3 is the address of the subrecord itself"
            );
        }
    }

    #[test]
    fn returns_the_input_word_as_rewritten_by_the_dispatcher() {
        let _recorder = install(0xfeedbeef);
        unsafe {
            assert_eq!(gateway_service18_request(0, 0, 0, 0), 0xfeedbeef);
        }
    }

    #[test]
    fn forwards_edge_case_argument_words_without_a_guard() {
        let _recorder = install(0);
        unsafe {
            for input in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff] {
                assert_eq!(gateway_service18_request(input, input, input, input), 0);
            }
            let inputs: Vec<u32> = OBSERVED.iter().map(|record| record[3]).collect();
            assert_eq!(inputs.as_slice(), &[0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff]);
            let arg2s: Vec<u32> = OBSERVED.iter().map(|record| record[1]).collect();
            assert_eq!(arg2s.as_slice(), inputs.as_slice());
        }
    }

    #[test]
    fn records_the_thunk_and_mirrored_body_addresses() {
        assert_eq!(SERVICE18_THUNK, 0x0803_7f20);
        assert_eq!(SERVICE18_ROM_ENTRY, 0x2200_41fc);
        assert_eq!(
            SERVICE18_MIRROR_ENTRY,
            0x0800_0000 + (SERVICE18_ROM_ENTRY - crate::kernel::thunks::ROM_BASE)
        );
    }

    #[test]
    fn thunk_table_names_this_protocol() {
        let entry = crate::kernel::thunks::ROM_THUNKS
            .iter()
            .find(|thunk| thunk.thunk_addr == SERVICE18_THUNK)
            .expect("the veneer is catalogued in kernel/thunks.rs");
        assert_eq!(entry.rom_target, SERVICE18_ROM_ENTRY);
        assert_eq!(entry.name, Some("gateway_service18_request"));
    }
}

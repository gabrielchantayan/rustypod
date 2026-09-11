//! Raw mask-ROM service-19 gateway request wrapper.
//!
//! `thunk_EXT_FUN_22004230` is the 8-byte ADS literal veneer at load address
//! `0x08037f08`: raw words are `e51ff004` (`ldr pc, [pc, #-4]`) and
//! `22004230`. The boot relocator copies `0x08000000..0x0800aed8` to IRAM, so
//! its target `0x22004230` mirrors the 48-byte body at `0x08004230` (ending
//! immediately before the sibling body at `0x08004260`).
//!
//! The body reserves seven words, writes its input at `sp + 24`, then passes
//! the six-word subrecord at `sp + 4` to the foreign gateway dispatcher:
//! `{ service = 19, output = 0, _, _, _, input }`. It reloads `output` after
//! dispatch. The three middle words are deliberately uninitialized exactly as
//! in the raw ARM body.
//!
//! Every ARM B/BL immediate in `osos.dec` was decoded: the veneer has nine
//! direct call sites, all unconditional `bl` (`0x080845ac`, `0x08084c28`,
//! `0x080c9c70`, `0x080e184c`, `0x082d965c`, `0x08393580`, `0x083935b0`,
//! `0x08393850`, `0x08393864`), with no predicated forms or tail branches.
//! No image word contains the veneer or mirror address; only the veneer
//! literal contains `0x22004230`. Callers pass an owned word before releasing
//! it, but the RTXC operation represented by selector 19 is not recovered, so
//! this module names the verified wire protocol rather than inventing it.
//!
//! # Deliberate deviation
//!
//! The raw body calls the foreign `0x08003660` literal veneer. This port uses
//! its established [`message_dispatch_veneer`] seam, preserving the writable
//! request ABI while letting target integration bind the unavailable service
//! dispatcher and host tests inspect it.

use core::mem::MaybeUninit;

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// osos load address of `thunk_EXT_FUN_22004230`.
pub const SERVICE19_THUNK: u32 = 0x0803_7f08;
/// IRAM target literal held by [`SERVICE19_THUNK`].
pub const SERVICE19_ROM_ENTRY: u32 = 0x2200_4230;
/// The target body's byte-identical osos mirror.
pub const SERVICE19_MIRROR_ENTRY: u32 = 0x0800_4230;

/// Gateway selector written at the start of the dispatch subrecord.
pub const GATEWAY_SERVICE_19: u32 = 19;

const FRAME_WORDS: usize = 7;
const REQUEST_START: usize = 1;
const SERVICE_WORD: usize = 0;
const OUTPUT_WORD: usize = 1;
const INPUT_WORD: usize = 5;

/// gateway_service19_request — original: `thunk_EXT_FUN_22004230` @
/// `0x08037f08` (8-byte veneer) → mirrored body `0x08004230` (48 bytes; nine
/// unconditional `bl` call sites).
///
/// Builds `{19, 0, _, _, _, input}` in the original seven-word frame, calls
/// the RTXC gateway dispatcher, and returns its post-dispatch output word.
/// The service's higher-level identity is deliberately unknown; `input` is
/// passed without a NULL, sentinel, or range guard, matching every caller.
///
/// # Safety
///
/// The target dispatcher interprets the selector-specific writable frame. On
/// device it must be installed through `message_dispatch_veneer`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_service19_request(input: u32) -> u32 {
    let mut frame = [MaybeUninit::<u32>::uninit(); FRAME_WORDS];
    let words = frame.as_mut_ptr().cast::<u32>();
    let request = words.add(REQUEST_START);

    // Exact raw-ARM store order: input at sp+24, output at sp+8, service at sp+4.
    words.add(REQUEST_START + INPUT_WORD).write(input);
    request.add(OUTPUT_WORD).write(0);
    request.add(SERVICE_WORD).write(GATEWAY_SERVICE_19);
    message_dispatch_veneer(request);
    request.add(OUTPUT_WORD).read()
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

    static mut OBSERVED: Vec<[u32; 3]> = Vec::new();
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
            request.add(OUTPUT_WORD).read(),
            request.add(INPUT_WORD).read(),
        ]);
        request.add(OUTPUT_WORD).write(OUTPUT_TO_WRITE);
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
    fn posts_service19_with_a_cleared_output_and_the_input_at_word_five() {
        let _recorder = install(0);
        unsafe { gateway_service19_request(0xdecafbad) };
        unsafe {
            assert_eq!(
                OBSERVED.as_slice(),
                &[[GATEWAY_SERVICE_19, 0, 0xdecafbad]],
                "the dispatcher receives the six-word subrecord, not frame word zero"
            );
        }
    }

    #[test]
    fn returns_the_output_the_dispatcher_writes() {
        let _recorder = install(0xfeedbeef);
        unsafe {
            assert_eq!(gateway_service19_request(0), 0xfeedbeef);
        }
    }

    #[test]
    fn forwards_edge_case_input_words_without_a_guard() {
        let _recorder = install(0);
        unsafe {
            for input in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff] {
                assert_eq!(gateway_service19_request(input), 0);
            }
            let inputs: Vec<u32> = OBSERVED.iter().map(|record| record[2]).collect();
            assert_eq!(inputs.as_slice(), &[0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff]);
        }
    }

    #[test]
    fn records_the_thunk_and_mirrored_body_addresses() {
        assert_eq!(SERVICE19_THUNK, 0x0803_7f08);
        assert_eq!(SERVICE19_ROM_ENTRY, 0x2200_4230);
        assert_eq!(
            SERVICE19_MIRROR_ENTRY,
            0x0800_0000 + (SERVICE19_ROM_ENTRY - crate::kernel::thunks::ROM_BASE)
        );
    }

    #[test]
    fn thunk_table_names_this_protocol() {
        let entry = crate::kernel::thunks::ROM_THUNKS
            .iter()
            .find(|thunk| thunk.thunk_addr == SERVICE19_THUNK)
            .expect("the veneer is catalogued in kernel/thunks.rs");
        assert_eq!(entry.rom_target, SERVICE19_ROM_ENTRY);
        assert_eq!(entry.name, Some("gateway_service19_request"));
    }
}

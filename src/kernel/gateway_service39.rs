//! Raw IRAM service-39 gateway request wrapper.
//!
//! `thunk_EXT_FUN_22003c28` is the 8-byte ADS literal veneer at load address
//! `0x08037eb0`: raw words are `e51ff004` (`ldr pc, [pc, #-4]`) and
//! `22003c28`. The boot relocator copies `0x08000000..0x0800aed8` to IRAM, so
//! its target `0x22003c28` mirrors the 52-byte body at `0x08003c28` (ending
//! immediately before data/instructions at `0x08003c5c`).
//!
//! The body reserves nine words, then passes the eight-word subrecord at
//! `sp + 4` to the foreign gateway dispatcher: `{ service = 39, output = 0,
//! first_input, _, _, _, _, second_input }`. The raw store order is
//! `first_input`, `output`, `service`, `second_input`; the four middle words
//! are deliberately uninitialized. It returns the dispatcher-written output.
//!
//! Every ARM B/BL immediate in `osos.dec` was decoded: the veneer has three
//! direct call sites, all unconditional `bl` (`0x08058510`, `0x0805851c`, and
//! `0x081f4b98`), with no predicated forms or tail branches. The RTXC operation
//! represented by selector 39 is not recovered, so this module names the
//! verified wire protocol rather than inventing it.
//!
//! # Deliberate deviation
//!
//! The raw body calls the foreign `0x08003660` literal veneer. This port uses
//! its established [`message_dispatch_veneer`] seam, preserving the writable
//! request ABI while letting target integration bind the unavailable service
//! dispatcher and host tests inspect it.

use core::mem::MaybeUninit;

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// osos load address of `thunk_EXT_FUN_22003c28`.
pub const SERVICE39_THUNK: u32 = 0x0803_7eb0;
/// IRAM target literal held by [`SERVICE39_THUNK`].
pub const SERVICE39_ROM_ENTRY: u32 = 0x2200_3c28;
/// The target body's byte-identical osos mirror.
pub const SERVICE39_MIRROR_ENTRY: u32 = 0x0800_3c28;

/// Gateway selector written at the start of the dispatch subrecord.
pub const GATEWAY_SERVICE_39: u32 = 39;

const FRAME_WORDS: usize = 9;
const REQUEST_START: usize = 1;
const SERVICE_WORD: usize = 0;
const OUTPUT_WORD: usize = 1;
const FIRST_INPUT_WORD: usize = 2;
const SECOND_INPUT_WORD: usize = 7;

/// gateway_service39_request — original: `thunk_EXT_FUN_22003c28` @
/// `0x08037eb0` (8-byte veneer) → mirrored body `0x08003c28` (52 bytes; three
/// unconditional `bl` call sites).
///
/// Builds `{39, 0, first_input, _, _, _, _, second_input}` in the original
/// nine-word frame, calls the RTXC gateway dispatcher, and returns its
/// post-dispatch output word. Both inputs pass without NULL, sentinel, or
/// range guards, matching every caller.
///
/// # Safety
///
/// The target dispatcher interprets the selector-specific writable frame. On
/// device it must be installed through `message_dispatch_veneer`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_service39_request(first_input: u32, second_input: u32) -> u32 {
    let mut frame = [MaybeUninit::<u32>::uninit(); FRAME_WORDS];
    let words = frame.as_mut_ptr().cast::<u32>();
    let request = words.add(REQUEST_START);

    // Exact raw-ARM store order: r0, output, selector, then r1.
    request.add(FIRST_INPUT_WORD).write(first_input);
    request.add(OUTPUT_WORD).write(0);
    request.add(SERVICE_WORD).write(GATEWAY_SERVICE_39);
    request.add(SECOND_INPUT_WORD).write(second_input);
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

    static mut OBSERVED: Vec<[u32; 4]> = Vec::new();
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
            request.add(FIRST_INPUT_WORD).read(),
            request.add(SECOND_INPUT_WORD).read(),
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
    fn posts_service39_with_cleared_output_and_both_input_words() {
        let _recorder = install(0);
        unsafe { gateway_service39_request(0xdecafbad, 0x12345678) };
        unsafe {
            assert_eq!(OBSERVED.as_slice(), &[[GATEWAY_SERVICE_39, 0, 0xdecafbad, 0x12345678]]);
        }
    }

    #[test]
    fn returns_the_output_the_dispatcher_writes() {
        let _recorder = install(0xfeedbeef);
        unsafe {
            assert_eq!(gateway_service39_request(0, 0), 0xfeedbeef);
        }
    }

    #[test]
    fn forwards_edge_case_input_words_without_a_guard() {
        let _recorder = install(0);
        let values = [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff];
        unsafe {
            for value in values {
                assert_eq!(gateway_service39_request(value, !value), 0);
            }
            let inputs: Vec<[u32; 2]> = OBSERVED.iter().map(|record| [record[2], record[3]]).collect();
            assert_eq!(inputs.as_slice(), &[
                [0, 0xffff_ffff], [1, 0xffff_fffe], [0x7fff_ffff, 0x8000_0000],
                [0x8000_0000, 0x7fff_ffff], [0xffff_fffe, 1], [0xffff_ffff, 0],
            ]);
        }
    }

    #[test]
    fn records_the_thunk_and_mirrored_body_addresses() {
        assert_eq!(SERVICE39_THUNK, 0x0803_7eb0);
        assert_eq!(SERVICE39_ROM_ENTRY, 0x2200_3c28);
        assert_eq!(
            SERVICE39_MIRROR_ENTRY,
            0x0800_0000 + (SERVICE39_ROM_ENTRY - crate::kernel::thunks::ROM_BASE)
        );
    }

    #[test]
    fn thunk_table_names_this_protocol() {
        let entry = crate::kernel::thunks::ROM_THUNKS
            .iter()
            .find(|thunk| thunk.thunk_addr == SERVICE39_THUNK)
            .expect("the veneer is catalogued in kernel/thunks.rs");
        assert_eq!(entry.rom_target, SERVICE39_ROM_ENTRY);
        assert_eq!(entry.name, Some("gateway_service39_request"));
    }
}

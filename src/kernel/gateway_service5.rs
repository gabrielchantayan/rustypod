//! Raw mask-ROM service-5 gateway request wrapper.
//!
//! `thunk_EXT_FUN_220040fc` is the 8-byte ADS literal veneer at load address
//! `0x08038080`: raw words are `e51ff004` (`ldr pc, [pc, #-4]`) and
//! `220040fc`. The boot relocator copies `0x08000000..0x0800aed8` to IRAM, so
//! its target mirrors the 60-byte body at `0x080040fc`.
//!
//! The body reserves nine words and passes the subrecord at `sp + 4` to the
//! foreign gateway dispatcher. It writes `{ service = 5, _, _, arg0, arg1,
//! _, output = 0, 1, 0 }`, then returns the post-dispatch output word. The
//! three unspecified subrecord words are deliberately uninitialized, as in
//! the raw ARM body.
//!
//! Raw ARM decoding establishes three plain inbound `bl` calls
//! (`0x08165c1c`, `0x08393154`, and `0x08393900`) and no predicated calls.
//! Ghidra's four-byte extent omits the veneer literal.
//!
//! # Deliberate deviation
//!
//! The mirrored body calls the foreign `0x08003660` dispatcher veneer. This
//! port uses its established [`message_dispatch_veneer`] seam; Rust therefore
//! has a normal return edge where the original veneer tail-branches.

use core::mem::MaybeUninit;

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// osos load address of `thunk_EXT_FUN_220040fc`.
pub const SERVICE5_THUNK: u32 = 0x0803_8080;
/// IRAM target literal held by [`SERVICE5_THUNK`].
pub const SERVICE5_ROM_ENTRY: u32 = 0x2200_40fc;
/// The target body's byte-identical osos mirror.
pub const SERVICE5_MIRROR_ENTRY: u32 = 0x0800_40fc;

/// Gateway selector written at the start of the dispatch subrecord.
pub const GATEWAY_SERVICE_5: u32 = 5;

const FRAME_WORDS: usize = 9;
const REQUEST_START: usize = 1;
const SERVICE_WORD: usize = 0;
const ARG0_WORD: usize = 3;
const ARG1_WORD: usize = 4;
const OUTPUT_WORD: usize = 6;
const FIXED_ONE_WORD: usize = 7;
const FIXED_ZERO_WORD: usize = 8;

/// gateway_service5_request — original: `thunk_EXT_FUN_220040fc` @
/// `0x08038080` (8-byte literal veneer) → mirrored body `0x080040fc` (60
/// bytes; three unconditional `bl` call sites, no predicated calls).
///
/// Builds the service-5 request `{5, _, _, arg0, arg1, _, 0, 1, 0}`, invokes
/// the RTXC dispatcher, and returns its post-dispatch output word. The
/// service's higher-level identity is not recovered, so both argument words
/// are forwarded without guards.
///
/// # Safety
///
/// The target dispatcher interprets this selector-specific writable frame.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_service5_request(arg0: u32, arg1: u32) -> u32 {
    let mut frame = [MaybeUninit::<u32>::uninit(); FRAME_WORDS];
    let words = frame.as_mut_ptr().cast::<u32>();
    let request = words.add(REQUEST_START);

    // Exact raw-ARM store order: arguments, fixed one, service, then output
    // and trailing zero. The remaining words are intentionally untouched.
    request.add(ARG0_WORD).write(arg0);
    request.add(ARG1_WORD).write(arg1);
    request.add(FIXED_ONE_WORD).write(1);
    request.add(SERVICE_WORD).write(GATEWAY_SERVICE_5);
    request.add(OUTPUT_WORD).write(0);
    request.add(FIXED_ZERO_WORD).write(0);
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
            request.add(ARG0_WORD).read(),
            request.add(ARG1_WORD).read(),
            request.add(OUTPUT_WORD).read(),
            request.add(FIXED_ONE_WORD).read(),
            request.add(FIXED_ZERO_WORD).read(),
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
    fn posts_service5_arguments_and_fixed_trailer() {
        let _recorder = install(0xfeed_beef);
        unsafe {
            assert_eq!(gateway_service5_request(0xdecafbad, 0x0123_4567), 0xfeed_beef);
            assert_eq!(
                OBSERVED.as_slice(),
                &[[GATEWAY_SERVICE_5, 0xdecafbad, 0x0123_4567, 0, 1, 0]],
            );
        }
    }

    #[test]
    fn forwards_boundary_argument_words_without_a_guard() {
        let _recorder = install(0);
        unsafe {
            for value in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
                assert_eq!(gateway_service5_request(value, !value), 0);
            }
            let args: Vec<[u32; 2]> = OBSERVED.iter().map(|record| [record[1], record[2]]).collect();
            assert_eq!(
                args.as_slice(),
                &[
                    [0, 0xffff_ffff],
                    [1, 0xffff_fffe],
                    [0x7fff_ffff, 0x8000_0000],
                    [0x8000_0000, 0x7fff_ffff],
                    [0xffff_ffff, 0],
                ],
            );
        }
    }
}

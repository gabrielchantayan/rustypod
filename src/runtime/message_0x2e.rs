//! Message-0x2e dispatcher wrapper — `thunk_EXT_FUN_22003be8` @
//! `0x08037e68` (8-byte literal veneer) → `FUN_08003be8` @ `0x08003be8`
//! (64-byte mirrored body).
//!
//! Raw veneer words are `e51ff004` (`ldr pc, [pc, #-4]`) and `22003be8`; the
//! next veneer starts at `0x08037e70`. The boot relocator copies the body into
//! IRAM, where it builds `{ 0x2e, 0, first_word, fourth_word, second_word,
//! third_word, fifth_word }`, calls the `0x08003660` RTXC dispatch veneer, and
//! returns the dispatcher-writable second word. The body ends immediately
//! before the next function at `0x08003c28`.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds four direct callers:
//! plain `bl` at `0x0805668c`, `0x080566a8`, `0x08086088`, and `0x0808b224`;
//! there are no predicated BL calls. The service represented by selector 0x2e
//! is not recovered, so this module names only its verified wire protocol.
//!
//! # Deliberate deviation
//!
//! The raw body calls the unported RTXC dispatcher via its literal veneer.
//! This port uses the existing installable `message_dispatch_veneer` seam,
//! preserving the writable record ABI while giving Rust a normal call edge.

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// osos load address of the ADS veneer.
pub const MESSAGE_0X2E_THUNK: u32 = 0x0803_7e68;
/// IRAM target literal in [`MESSAGE_0X2E_THUNK`].
pub const MESSAGE_0X2E_ROM_ENTRY: u32 = 0x2200_3be8;
/// Byte-identical osos mirror of [`MESSAGE_0X2E_ROM_ENTRY`].
pub const MESSAGE_0X2E_MIRROR_ENTRY: u32 = 0x0800_3be8;
/// RTXC selector placed in the first request word.
pub const MESSAGE_COMMAND: u32 = 0x2e;

const RETURN_WORD: usize = 1;

/// dispatch_message_0x2e — original: `thunk_EXT_FUN_22003be8` @ `0x08037e68`
/// (8-byte veneer) → `FUN_08003be8` @ `0x08003be8` (64 bytes; four plain
/// `bl` callers and zero predicated BL callers).
///
/// Builds the exact seven-word request `{ 0x2e, 0, first_word, fourth_word,
/// second_word, third_word, fifth_word }`, dispatches it through the RTXC
/// message seam, and returns word one after dispatch. The selector-specific
/// service identity is deliberately unknown; every input word is forwarded
/// without validation.
///
/// # Safety
///
/// The RTXC dispatcher interprets and may mutate this selector-specific,
/// writable request record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_message_0x2e(
    first_word: u32,
    second_word: u32,
    third_word: u32,
    fourth_word: u32,
    fifth_word: u32,
) -> u32 {
    let mut request = [
        MESSAGE_COMMAND,
        0,
        first_word,
        fourth_word,
        second_word,
        third_word,
        fifth_word,
    ];
    message_dispatch_veneer(request.as_mut_ptr());
    request[RETURN_WORD]
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

    static mut OBSERVED: Vec<[u32; 7]> = Vec::new();
    static mut RETURN_VALUE: u32 = 0;

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
            request.add(0).read(),
            request.add(1).read(),
            request.add(2).read(),
            request.add(3).read(),
            request.add(4).read(),
            request.add(5).read(),
            request.add(6).read(),
        ]);
        request.add(RETURN_WORD).write(RETURN_VALUE);
    }

    fn install(return_value: u32) -> Recorder {
        let lock = DISPATCH_OPS_LOCK.lock();
        let saved = unsafe { MESSAGE_DISPATCH_VENEER_OPS };
        unsafe {
            OBSERVED = Vec::new();
            RETURN_VALUE = return_value;
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps {
                dispatch: recording_dispatch,
            };
        }
        Recorder { _lock: lock, saved }
    }

    #[test]
    fn posts_the_exact_seven_word_request() {
        let _recorder = install(0);
        unsafe { dispatch_message_0x2e(1, 4, 0x200, 0x1234_5678, 0) };
        unsafe {
            assert_eq!(
                OBSERVED.as_slice(),
                &[[0x2e, 0, 1, 0x1234_5678, 4, 0x200, 0]]
            );
        }
    }

    #[test]
    fn returns_the_second_word_as_rewritten_by_dispatcher() {
        let _recorder = install(0xfeed_beef);
        unsafe {
            assert_eq!(dispatch_message_0x2e(0, 0, 0, 0, 0), 0xfeed_beef);
        }
    }

    #[test]
    fn forwards_edge_words_without_validation() {
        let _recorder = install(0);
        unsafe {
            for word in [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
                dispatch_message_0x2e(word, word, word, word, word);
            }
            for (index, word) in [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff]
                .iter()
                .enumerate()
            {
                assert_eq!(
                    OBSERVED[index],
                    [0x2e, 0, *word, *word, *word, *word, *word]
                );
            }
        }
    }

    #[test]
    fn records_verified_thunk_and_mirror_addresses() {
        assert_eq!(MESSAGE_0X2E_THUNK, 0x0803_7e68);
        assert_eq!(MESSAGE_0X2E_ROM_ENTRY, 0x2200_3be8);
        assert_eq!(MESSAGE_0X2E_MIRROR_ENTRY, 0x0800_3be8);
    }
}

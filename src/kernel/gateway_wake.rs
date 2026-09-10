//! The RTXC kernel-gateway **wake** stub — service 1, one object id.
//!
//! The literal veneer `thunk_EXT_FUN_22004368` is at load address
//! **0x08037ea8**. Ghidra reports 4 bytes; raw words prove its true extent is
//! 8 bytes: `e51ff004` (`ldr pc,[pc,#-4]`) followed by the target literal
//! `0x22004368`, with the next veneer opening at 0x08037eb0. It reaches the
//! 52-byte IRAM body at 0x22004368, mirrored in osos at 0x08004368 by the
//! boot relocator at 0x080046e0.
//!
//! Raw ARM at 0x08004368 reserves five words, writes the request record
//! `{1, 0, object, 0, _}`, calls the message-dispatch veneer at 0x08003660,
//! and returns the dispatcher-written status word. The trailing word remains
//! uninitialized solely to retain the original 8-byte stack alignment.
//!
//! Decoding every ARM B/BL encoding in osos.dec finds 11 `bl` callers: 10
//! unconditional (0x0806a59c, 0x0806b9e8, 0x080860f8, 0x080c9b98,
//! 0x080cb730, 0x080e4404, 0x08368324, 0x0839346c, 0x083939a0,
//! 0x083939c0) and one `blne` at 0x081a595c. That predicated caller first
//! tests a flag and supplies fixed object id 18; the stub itself has no
//! guard. Two tail branches also reach the veneer: `bmi` at 0x0805699c and
//! the bare alias `b` at 0x080569a4. The only data word equal to the IRAM
//! entry is the veneer literal at 0x08037eac, so this is not a virtual
//! dispatch entry.
//!
//! ## Naming and deviation
//!
//! Selector 1 and the record layout are raw-byte facts. “Wake” is the
//! call-site reading: the two tail paths are csem's negative-count wake and
//! its raw-id alias. The foreign RTXC dispatcher is not present in osos, so
//! its service-table identity is not claimed. As with the sibling
//! `gateway_signal_object`, this port calls the existing installable
//! `message_dispatch_veneer` seam instead of branching into IRAM.

use core::mem::MaybeUninit;

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

/// osos load address of the literal veneer (`thunk_EXT_FUN_22004368`).
pub const WAKE_THUNK: u32 = 0x0803_7ea8;
/// The veneer target in relocated IRAM.
pub const WAKE_ROM_ENTRY: u32 = 0x2200_4368;
/// The same body before the boot relocator copies it to IRAM.
pub const WAKE_MIRROR_ENTRY: u32 = 0x0800_4368;
/// Request word 0: the RTXC service selector.
pub const GATEWAY_SERVICE_WAKE: u32 = 1;

const REQUEST_WORDS: usize = 5;
const SERVICE_WORD: usize = 0;
const STATUS_WORD: usize = 1;
const OBJECT_WORD: usize = 2;
const RESERVED_ZERO_WORD: usize = 3;

/// gateway_wake_object — original body @ 0x08004368 (52 bytes), reached by
/// the 8-byte load-address-0x08037ea8 literal veneer (11 `bl` callers: 10
/// unconditional and one `blne`, plus two tail branches).
///
/// Builds `{1, 0, object, 0, _}` in the original store order, dispatches it
/// through 0x08003660, then returns the status word written by the dispatcher.
/// No object-id guard or mask: the sole predicated caller gates its own call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn gateway_wake_object(object: u32) -> u32 {
    let mut request = [MaybeUninit::<u32>::uninit(); REQUEST_WORDS];
    let words = request.as_mut_ptr().cast::<u32>();
    words.add(OBJECT_WORD).write(object);
    words.add(RESERVED_ZERO_WORD).write(0);
    words.add(STATUS_WORD).write(0);
    words.add(SERVICE_WORD).write(GATEWAY_SERVICE_WAKE);
    message_dispatch_veneer(words);
    words.add(STATUS_WORD).read()
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
    static mut STATUS_TO_WRITE: u32 = 0;

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
            request.read(),
            request.add(1).read(),
            request.add(2).read(),
            request.add(3).read(),
        ]);
        request.add(STATUS_WORD).write(STATUS_TO_WRITE);
    }

    fn install(status: u32) -> Recorder {
        let lock = DISPATCH_OPS_LOCK.lock();
        let saved = unsafe { MESSAGE_DISPATCH_VENEER_OPS };
        unsafe {
            OBSERVED = Vec::new();
            STATUS_TO_WRITE = status;
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps {
                dispatch: recording_dispatch,
            };
        }
        Recorder { _lock: lock, saved }
    }

    #[test]
    fn posts_selector_one_with_a_cleared_status_and_reserved_word() {
        let _recorder = install(0);
        unsafe {
            assert_eq!(gateway_wake_object(0x12), 0);
            assert_eq!(
                OBSERVED.as_slice(),
                &[[GATEWAY_SERVICE_WAKE, 0, 0x12, 0]],
                "record is {{1, 0, object, 0}}, dispatched exactly once"
            );
        }
    }

    #[test]
    fn returns_the_dispatcher_status_for_all_object_word_values() {
        let _recorder = install(0xa5);
        unsafe {
            for object in [0u32, 18, 0x8000_0000, 0xffff_ffff] {
                assert_eq!(gateway_wake_object(object), 0xa5);
            }
            let objects: Vec<u32> = OBSERVED.iter().map(|record| record[2]).collect();
            assert_eq!(objects.as_slice(), &[0, 18, 0x8000_0000, 0xffff_ffff]);
        }
    }

    #[test]
    fn records_the_veneer_and_mirrored_body_addresses() {
        assert_eq!(WAKE_THUNK, 0x0803_7ea8);
        assert_eq!(WAKE_ROM_ENTRY, 0x2200_4368);
        const OSOS_BASE: u32 = 0x0800_0000;
        const RELOCATED_BYTES: u32 = 0xaed8;
        let offset = WAKE_ROM_ENTRY - crate::kernel::thunks::ROM_BASE;
        assert_eq!(WAKE_MIRROR_ENTRY, OSOS_BASE + offset);
        assert!(offset < RELOCATED_BYTES, "inside the relocated block");
    }

    #[test]
    fn the_thunk_table_names_the_wake_entry() {
        let entry = crate::kernel::thunks::ROM_THUNKS
            .iter()
            .find(|thunk| thunk.thunk_addr == WAKE_THUNK)
            .expect("the veneer is catalogued in kernel/thunks.rs");
        assert_eq!(entry.rom_target, WAKE_ROM_ENTRY);
        assert_eq!(entry.name, Some("wake_object"));
    }
}

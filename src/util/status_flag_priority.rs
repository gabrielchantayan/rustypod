//! Status-flag priority selector.
//!
//! `status_flag_priority` is retailOS `FUN_082b1fd4` at load address
//! **0x082b1fd4**, 64 bytes (`0x082b1fd4..0x082b2014`; the separately entered
//! next function begins at `0x082b2014`). Decoding every ARM B/BL-immediate
//! word in `osos.dec` finds six direct inbound calls, all unconditional plain
//! `bl` at `0x083875b8`, `0x08387a28`, `0x0838a624`, `0x0838ab24`,
//! `0x0838adec`, and `0x08391790`; no predicated call targets this entry.
//!
//! # Algorithm
//!
//! The function reads the aligned 16-bit flag word at `object + 0x1c` and
//! stores a one-byte priority code at `object + 0x1e`. Bit 0 has priority 5,
//! then bits 2, 3, and 1 select 1, 2, and 3 respectively; no selected bit
//! yields 4. It has no NULL guard.
//!
//! # Deliberate deviations
//!
//! None. The Rust port uses volatile accesses so the externally owned
//! target-width object's load and store remain observable to LLVM.

const FLAGS_OFFSET: usize = 0x1c;
const PRIORITY_OFFSET: usize = 0x1e;

/// Selects and stores the highest-priority status code from an object's flags.
///
/// Original: `FUN_082b1fd4` at load address `0x082b1fd4`, 64 bytes, with six
/// verified plain-`bl` callers.
///
/// # Safety
///
/// `object` must be non-null and valid for an aligned `u16` read at `+0x1c`
/// and a byte write at `+0x1e`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.status_flag_priority")]
#[inline(never)]
pub unsafe extern "C" fn status_flag_priority(object: *mut u8) {
    let flags = unsafe { (object.add(FLAGS_OFFSET) as *const u16).read_volatile() };
    let priority = if flags & 1 != 0 {
        5
    } else if flags & 4 != 0 {
        1
    } else if flags & 8 != 0 {
        2
    } else if flags & 2 != 0 {
        3
    } else {
        4
    };

    unsafe { object.add(PRIORITY_OFFSET).write_volatile(priority); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct StatusObject {
        _prefix: [u8; FLAGS_OFFSET],
        flags: u16,
        priority: u8,
        guard: u8,
    }

    const _: () = assert!(core::mem::offset_of!(StatusObject, flags) == FLAGS_OFFSET);
    const _: () = assert!(core::mem::offset_of!(StatusObject, priority) == PRIORITY_OFFSET);

    fn select(flags: u16) -> StatusObject {
        let mut object = StatusObject {
            _prefix: [0; FLAGS_OFFSET],
            flags,
            priority: 0xa5,
            guard: 0x5a,
        };
        unsafe { status_flag_priority((&mut object as *mut StatusObject).cast()); }
        object
    }

    #[test]
    fn selects_each_status_flag_in_its_observed_priority_order() {
        for (flags, expected) in [(0, 4), (2, 3), (8, 2), (4, 1), (1, 5)] {
            assert_eq!(select(flags).priority, expected, "flags {flags:#06x}");
        }
    }

    #[test]
    fn higher_priority_flags_win_and_unrelated_bits_are_ignored() {
        for (flags, expected) in [(0x0006, 1), (0x000a, 2), (0x000e, 1), (0x000f, 5), (0xfff0, 4)] {
            let object = select(flags);
            assert_eq!(object.priority, expected, "flags {flags:#06x}");
            assert_eq!(object.guard, 0x5a, "flags {flags:#06x}");
        }
    }
}

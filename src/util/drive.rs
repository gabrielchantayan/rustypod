//! drive_set_last_lba — original: `FUN_0813b6ec` @ 0x0813b6ec (8 bytes;
//! 1 `bl` call site: the drive-descriptor builder `FUN_08283a7c` @
//! 0x08283be8).
//!
//! A two-instruction field setter:
//!
//! ```text
//! str r1, [r0, #0x58]   @ drive->last_lba = last_lba
//! bx  lr
//! ```
//!
//! `drive` is the 0x68-byte NAND-flash drive descriptor that
//! `FUN_08283a7c` allocates (`operator_new(0x68)`), tags with the vtable
//! literal `DAT_08283c18` and constructs through `FUN_0813b650` @
//! 0x0813b650, which fills in the identity strings "NAND_FLASH_DRIVE"
//! at +0x13 and the serial "12345678901234567890" at +0x43, plus the
//! word 0x2000000 at +0x60. The builder then sets the geometry pair:
//!
//! ```c
//! FUN_0813b5d4(drive, 0x1000);        // +0x64 = unit (block) size
//! FUN_0813b6ec(drive, unit_count - 1);// +0x58 = last unit index
//! ```
//!
//! where `unit_count` comes from `FUN_082bcb74` @ 0x082bcb74 — total
//! sectors (a storage-driver word) divided by sectors-per-0x1000-unit,
//! i.e. the capacity in 0x1000-byte blocks. The pair is exactly the
//! READ CAPACITY response shape (last logical block address + block
//! length), so +0x58 is named `last_lba`.
//!
//! The word is written nowhere else for this class: the `+0x58` stores
//! of 4/5 and the 1/3/4/5 state comparisons in `FUN_08283c1c` /
//! `FUN_08283d20` belong to a different (transfer-state) object — its
//! accessors `FUN_0816607c`/`FUN_081213dc` touch +0x30/+0x44, offsets
//! that fall inside this descriptor's serial string, so the layouts are
//! incompatible.
//!
//! Sits immediately before the util/berec.rs big-endian record reader
//! cluster @ 0x0813b714..0x0813b7b0 and the util/inner_state.rs query
//! wrappers @ 0x0813b7c4/0x0813b7d0 but is NOT one of them: no record
//! handle, no +0x40 inner forwarding — a plain descriptor setter, so it
//! gets its own file (the inner_state.rs precedent).
//!
//! Deviation: none beyond the crate-standard frame-pointer prologue.
//! Byte-offset addressing on a `*mut u8` (the util/state_flags.rs
//! precedent) keeps the layout exact on a 64-bit test host.

/// Byte offset of the last-logical-block-address word inside the drive
/// descriptor.
const LAST_LBA: usize = 0x58;

/// drive_set_last_lba — original: `FUN_0813b6ec` @ 0x0813b6ec (8 bytes).
///
/// Stores `last_lba` (the drive's capacity in 0x1000-byte units, minus
/// one) into the descriptor word at +0x58. Returns nothing (the
/// original leaves r0 = drive, but the sole caller discards it).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn drive_set_last_lba(drive: *mut u8, last_lba: u32) {
    (drive.add(LAST_LBA) as *mut u32).write(last_lba);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// Descriptor size the builder allocates (`operator_new(0x68)`).
    const DRIVE_LEN: usize = 0x68;
    const SENTINEL: u8 = 0xa5;

    struct Fixture {
        drive: [u8; DRIVE_LEN],
    }

    impl Fixture {
        fn new() -> Self {
            Fixture { drive: [SENTINEL; DRIVE_LEN] }
        }
        fn set(&mut self, last_lba: u32) {
            unsafe { drive_set_last_lba(self.drive.as_mut_ptr(), last_lba) }
        }
        fn last_lba(&self) -> u32 {
            u32::from_le_bytes(self.drive[LAST_LBA..LAST_LBA + 4].try_into().unwrap())
        }
    }

    #[test]
    fn stores_the_value_into_the_last_lba_word() {
        let mut fixture = Fixture::new();
        fixture.set(0x1fff); // 32 MiB of 0x1000-byte units, minus one
        assert_eq!(fixture.last_lba(), 0x1fff);
    }

    #[test]
    fn touches_only_the_last_lba_word() {
        let mut fixture = Fixture::new();
        fixture.set(0xdead_beef);
        for offset in 0..DRIVE_LEN {
            let expect = if (LAST_LBA..LAST_LBA + 4).contains(&offset) {
                [0xef, 0xbe, 0xad, 0xde][offset - LAST_LBA]
            } else {
                SENTINEL
            };
            assert_eq!(fixture.drive[offset], expect, "drive +{offset:#x}");
        }
    }

    #[test]
    fn overwrites_a_previous_value() {
        let mut fixture = Fixture::new();
        fixture.set(0x1fff);
        fixture.set(7);
        assert_eq!(fixture.last_lba(), 7);
    }

    #[test]
    fn round_trips_edge_values() {
        let mut fixture = Fixture::new();
        for value in [0u32, 1, u32::MAX] {
            fixture.set(value);
            assert_eq!(fixture.last_lba(), value);
        }
    }
}

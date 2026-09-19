//! `indexed_state_status` — original: `FUN_080cc64c` @ `0x080cc64c`
//! (68 bytes, `0x080cc64c..0x080cc690`; the pointer-table literal begins at
//! `0x080cc690`, and `0x080cc694` begins the next function).
//!
//! Raw ARM decoding finds four inbound direct plain `bl` calls and no
//! predicated inbound `bl` calls; the body has no outgoing calls.
//!
//! Selects a state record through the retail 0x18c-byte-strided pointer table.
//! Mode zero returns the low 27 bits of the word at +0xa98, and mode one
//! returns the word at +0xb18. Other modes return retailOS error 0xffffff06
//! without writing the output pointer. No deliberate behavioral deviations.

use crate::util::indexed_state_set_and_poll::indexed_state_table;

const STATE_RECORD_STRIDE_WORDS: isize = 0x18c / 4;
const PRIMARY_STATUS_OFFSET: usize = 0xa98;
const SECONDARY_STATUS_OFFSET: usize = 0xb18;
const PRIMARY_STATUS_MASK: u32 = 0x07ff_ffff;
const ERROR_INVALID_STATUS_MODE: u32 = 0xffff_ff06;

/// Reads a mode-selected status word from the state record selected by the
/// signed halfword ABI selector.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_state_status(selector: i16, mode: u32, out: *mut u32) -> u32 {
    let record = indexed_state_table()
        .offset(selector as isize * STATE_RECORD_STRIDE_WORDS)
        .read_volatile() as usize as *const u8;

    let value = match mode {
        0 => record.add(PRIMARY_STATUS_OFFSET).cast::<u32>().read_volatile() & PRIMARY_STATUS_MASK,
        1 => record.add(SECONDARY_STATUS_OFFSET).cast::<u32>().read_volatile(),
        _ => return ERROR_INVALID_STATUS_MODE,
    };
    out.write(value);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::util::indexed_state_set_and_poll::{INDEXED_STATE_TABLE, INDEXED_STATE_TABLE_TEST_LOCK};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::INDEXED_STATE_STATUS, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    unsafe fn install_fixture() -> Option<*mut u8> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0, FIXTURE_LEN);
        let table = base.cast::<u32>();
        table.write(base.add(0x200) as u32);
        table.add(99).write(base.add(0x400) as u32);
        INDEXED_STATE_TABLE = table;
        Some(base)
    }

    #[test]
    fn reads_masked_primary_and_unmasked_secondary_statuses() {
        let _lock = INDEXED_STATE_TABLE_TEST_LOCK.lock();
        let Some(base) = (unsafe { install_fixture() }) else {
            assert!(note_missing_u32_fixture("util/indexed_state_status"));
            return;
        };
        unsafe {
            base.add(0x200 + PRIMARY_STATUS_OFFSET).cast::<u32>().write(0xf923_4567);
            base.add(0x400 + SECONDARY_STATUS_OFFSET).cast::<u32>().write(0xdead_beef);
        }
        let mut out = 0;

        assert_eq!(unsafe { indexed_state_status(0, 0, &mut out) }, 0);
        assert_eq!(out, 0x0123_4567);
        assert_eq!(unsafe { indexed_state_status(1, 1, &mut out) }, 0);
        assert_eq!(out, 0xdead_beef);
    }

    #[test]
    fn invalid_mode_preserves_output_after_record_lookup() {
        let _lock = INDEXED_STATE_TABLE_TEST_LOCK.lock();
        let Some(_) = (unsafe { install_fixture() }) else {
            assert!(note_missing_u32_fixture("util/indexed_state_status"));
            return;
        };
        let mut out = 0xa5a5_5a5a;

        assert_eq!(unsafe { indexed_state_status(0, 2, &mut out) }, ERROR_INVALID_STATUS_MODE);
        assert_eq!(out, 0xa5a5_5a5a);
    }
}

//! `indexed_state_set_and_poll` — original: `FUN_080d39a0` @ `0x080d39a0`
//! (92 bytes, `0x080d39a0..0x080d39fc`; the literal pool at `0x080d39fc`
//! starts immediately after `bx lr`, and `mov r1,#99` at `0x080d3a00` begins
//! the next function). Raw ARM decoding finds four inbound direct plain `bl`
//! calls at `0x08039a24`, `0x080a6100`, `0x080a6138`, and `0x080aa03c`, all
//! unconditional; there are no predicated inbound `bl` calls and no outgoing
//! calls.
//!
//! Selects a 0x18c-byte-strided state record through the retail pointer table,
//! stores a requested state at +0x400, and, only for state one, polls that
//! volatile word for at most ten reads until it remains one. It returns zero
//! for state zero or acknowledged state one, one for other requests, and three
//! when the state-one write was superseded before the polling bound expired.
//! Host builds replace the fixed retail table address with a test seam. No
//! deliberate behavioral deviations.

const RETAIL_STATE_TABLE: *const u32 = 0x08b2_f648 as *const u32;
const STATE_RECORD_STRIDE: usize = 0x18c;
const REQUEST_STATE_OFFSET: usize = 0x400;
const POLL_LIMIT: u32 = 10;

#[cfg(not(target_os = "none"))]
pub static mut INDEXED_STATE_TABLE: *const u32 = core::ptr::null();

#[inline(always)]
unsafe fn state_table() -> *const u32 {
    #[cfg(target_os = "none")]
    return RETAIL_STATE_TABLE;
    #[cfg(not(target_os = "none"))]
    return core::ptr::addr_of!(INDEXED_STATE_TABLE).read_volatile();
}

/// Stores `requested_state` in the selected retail state record and polls an
/// acknowledgement for state one. `selector` is the signed halfword received
/// in r0; the table and record pointers retain retailOS's unchecked ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_state_set_and_poll(selector: i16, requested_state: i32) -> u32 {
    let record = state_table()
        .offset(selector as isize * (STATE_RECORD_STRIDE / 4) as isize)
        .read_volatile() as usize as *mut u8;
    let state = record.add(REQUEST_STATE_OFFSET).cast::<u32>();

    if requested_state == 0 {
        state.write_volatile(0);
        return 0;
    }
    if requested_state != 1 { return 1; }

    state.write_volatile(1);
    let mut remaining = POLL_LIMIT;
    while state.read_volatile() != 1 {
        remaining -= 1;
        if remaining == 0 { return 3; }
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::INDEXED_STATE_SET_AND_POLL, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn install_fixture() -> Option<*mut u8> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0, FIXTURE_LEN);
        let table = base.cast::<u32>();
        table.write(base.add(0x100) as u32);
        INDEXED_STATE_TABLE = table;
        Some(base)
    }

    #[test]
    fn zero_request_clears_the_selected_record_state() {
        let _lock = LOCK.lock();
        let Some(base) = (unsafe { install_fixture() }) else {
            assert!(note_missing_u32_fixture("util/indexed_state_set_and_poll"));
            return;
        };
        unsafe { base.add(0x500).cast::<u32>().write(0xdead_beef) };

        assert_eq!(unsafe { indexed_state_set_and_poll(0, 0) }, 0);
        assert_eq!(unsafe { base.add(0x500).cast::<u32>().read() }, 0);
    }

    #[test]
    fn one_request_sets_state_and_returns_when_acknowledged() {
        let _lock = LOCK.lock();
        let Some(base) = (unsafe { install_fixture() }) else {
            assert!(note_missing_u32_fixture("util/indexed_state_set_and_poll"));
            return;
        };

        assert_eq!(unsafe { indexed_state_set_and_poll(0, 1) }, 0);
        assert_eq!(unsafe { base.add(0x500).cast::<u32>().read() }, 1);
    }

    #[test]
    fn other_requests_leave_the_selected_record_unchanged() {
        let _lock = LOCK.lock();
        let Some(base) = (unsafe { install_fixture() }) else {
            assert!(note_missing_u32_fixture("util/indexed_state_set_and_poll"));
            return;
        };
        unsafe { base.add(0x500).cast::<u32>().write(0x1357_9bdf) };

        for requested_state in [-1, 2, i32::MAX] {
            assert_eq!(unsafe { indexed_state_set_and_poll(0, requested_state) }, 1);
            assert_eq!(unsafe { base.add(0x500).cast::<u32>().read() }, 0x1357_9bdf);
        }
    }
}

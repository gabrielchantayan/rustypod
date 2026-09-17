//! `quoted_input_candidate_find` — original: `FUN_082940b0` @ `0x082940b0`
//! (108 bytes; four inbound plain `bl` calls and no predicated `bl` calls).
//!
//! # Algorithm
//!
//! If the owner's nonzero candidate-order index selects an order word from the
//! table at `0x089d04bc`, visit its four byte-sized candidate indexes in order.
//! Invoke each selected candidate's vtable slot `+0x14` with the supplied
//! selector, and return the first candidate whose method returns nonzero.
//! Return NULL when the order index is zero or every candidate declines.
//!
//! Raw words establish the `0x082940b0..0x0829411c` extent and the indirect
//! `blx r2` at vtable slot `+0x14`; the four direct callers are
//! `0x08292ffc`, `0x08293e68`, `0x08293f20`, and `0x08294348`.
//! Deliberate deviation: host pointers are native-width, so `repr(C)` keeps
//! target field order while host fixtures use typed vtable entries instead of
//! target-width function-pointer words.

/// Owner layout consumed by [`quoted_input_candidate_find`].
#[repr(C)]
pub struct QuotedInputCandidateOwner {
    /// Target bytes `+0x00..+0x37`, not read here.
    pub unresolved_00_37: [u8; 0x38],
    /// Target words `+0x38..+0x47`, selected by each order byte.
    pub candidates: [*mut QuotedInputCandidate; 4],
    /// Target bytes after the candidate words through `+0xc3`.
    pub unresolved_after_candidates: [u8; 0x7c],
    /// Target word `+0xc4`; zero bypasses the lookup.
    pub candidate_order_index: u32,
}

/// Candidate object whose first word is a vtable.
#[repr(C)]
pub struct QuotedInputCandidate {
    pub vtable: *const QuotedInputCandidateVtable,
}

/// Recovered prefix of a candidate vtable.
#[repr(C)]
pub struct QuotedInputCandidateVtable {
    /// Slots `+0x00..+0x10`, not used here.
    pub unresolved_00_10: [usize; 5],
    /// Slot `+0x14`: reports whether this candidate accepts the selector.
    pub accepts_selector: unsafe extern "C" fn(*mut QuotedInputCandidate, u32) -> u32,
}

/// Firmware candidate-order table used as `table[index - 1]`.
#[cfg(target_os = "none")]
pub static mut QUOTED_INPUT_CANDIDATE_ORDER_TABLE: *const *const u8 =
    0x089d_04bc as *const *const u8;

/// Host tests install a native fixture table here.
#[cfg(not(target_os = "none"))]
pub static mut QUOTED_INPUT_CANDIDATE_ORDER_TABLE: *const *const u8 = core::ptr::null();

/// Finds the first ordered candidate whose slot `+0x14` accepts `selector`.
///
/// # Safety
///
/// `owner` must reference a valid target-layout owner. When its order index is
/// nonzero, the configured table entry must reference four readable bytes and
/// every selected candidate must have a readable vtable and callable slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn quoted_input_candidate_find(
    owner: *mut QuotedInputCandidateOwner,
    selector: u32,
) -> *mut QuotedInputCandidate {
    let order_index = core::ptr::addr_of!((*owner).candidate_order_index).read_volatile();
    if order_index == 0 {
        return core::ptr::null_mut();
    }

    let table = core::ptr::addr_of!(QUOTED_INPUT_CANDIDATE_ORDER_TABLE).read_volatile();
    let order = table.add(order_index as usize - 1).read_volatile();
    for byte_index in 0..4 {
        let candidate_index = order.add(byte_index).read_volatile() as usize;
        let candidate = core::ptr::addr_of!((*owner).candidates)
            .cast::<*mut QuotedInputCandidate>()
            .add(candidate_index)
            .read_volatile();
        let vtable = core::ptr::addr_of!((*candidate).vtable).read_volatile();
        if ((*vtable).accepts_selector)(candidate, selector) != 0 {
            return candidate;
        }
    }

    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static TABLE_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_SELECTORS: [u32; 4] = [0; 4];
    static mut CALLS: usize = 0;
    static mut ACCEPT_INDEX: usize = usize::MAX;

    unsafe extern "C" fn accept_configured_candidate(
        candidate: *mut QuotedInputCandidate,
        selector: u32,
    ) -> u32 {
        let call = CALLS;
        SEEN_SELECTORS[call] = selector;
        CALLS += 1;
        (ACCEPT_INDEX < 4 && candidate == addr_of_mut!(CANDIDATES[ACCEPT_INDEX])) as u32
    }

    static VTABLE: QuotedInputCandidateVtable = QuotedInputCandidateVtable {
        unresolved_00_10: [0; 5],
        accepts_selector: accept_configured_candidate,
    };
    static mut CANDIDATES: [QuotedInputCandidate; 4] = [
        QuotedInputCandidate { vtable: &VTABLE },
        QuotedInputCandidate { vtable: &VTABLE },
        QuotedInputCandidate { vtable: &VTABLE },
        QuotedInputCandidate { vtable: &VTABLE },
    ];
    static ORDER: [u8; 4] = [2, 0, 3, 1];
    static mut TABLE: [*const u8; 1] = [ORDER.as_ptr()];

    fn install_fixture(accept_index: usize) -> MutexGuard<'static, ()> {
        let guard = TABLE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(SEEN_SELECTORS).write([0; 4]);
            CALLS = 0;
            ACCEPT_INDEX = accept_index;
            addr_of_mut!(QUOTED_INPUT_CANDIDATE_ORDER_TABLE).write(addr_of_mut!(TABLE).cast());
        }
        guard
    }

    fn restore_fixture(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(QUOTED_INPUT_CANDIDATE_ORDER_TABLE).write(core::ptr::null()) };
        drop(guard);
    }

    #[test]
    fn checks_candidates_in_order_and_returns_the_first_accepting_one() {
        let guard = install_fixture(3);
        let mut owner = QuotedInputCandidateOwner {
            unresolved_00_37: [0; 0x38],
            candidates: unsafe { [addr_of_mut!(CANDIDATES[0]), addr_of_mut!(CANDIDATES[1]), addr_of_mut!(CANDIDATES[2]), addr_of_mut!(CANDIDATES[3])] },
            unresolved_after_candidates: [0; 0x7c],
            candidate_order_index: 1,
        };
        let found = unsafe { quoted_input_candidate_find(&mut owner, 0xfeed_beef) };
        assert_eq!(found, unsafe { addr_of_mut!(CANDIDATES[3]) });
        unsafe {
            assert_eq!(CALLS, 3);
            assert_eq!(addr_of!(SEEN_SELECTORS).read()[..3], [0xfeed_beef; 3]);
        }
        restore_fixture(guard);
    }

    #[test]
    fn zero_order_index_skips_the_table_and_all_candidates() {
        let guard = install_fixture(usize::MAX);
        let mut owner = QuotedInputCandidateOwner {
            unresolved_00_37: [0; 0x38],
            candidates: unsafe { [addr_of_mut!(CANDIDATES[0]), addr_of_mut!(CANDIDATES[1]), addr_of_mut!(CANDIDATES[2]), addr_of_mut!(CANDIDATES[3])] },
            unresolved_after_candidates: [0; 0x7c],
            candidate_order_index: 0,
        };
        assert!(unsafe { quoted_input_candidate_find(&mut owner, 7) }.is_null());
        assert_eq!(unsafe { CALLS }, 0);
        restore_fixture(guard);
    }

    #[test]
    fn returns_null_after_four_rejections() {
        let guard = install_fixture(usize::MAX);
        let mut owner = QuotedInputCandidateOwner {
            unresolved_00_37: [0; 0x38],
            candidates: unsafe { [addr_of_mut!(CANDIDATES[0]), addr_of_mut!(CANDIDATES[1]), addr_of_mut!(CANDIDATES[2]), addr_of_mut!(CANDIDATES[3])] },
            unresolved_after_candidates: [0; 0x7c],
            candidate_order_index: 1,
        };
        assert!(unsafe { quoted_input_candidate_find(&mut owner, 9) }.is_null());
        unsafe { assert_eq!(CALLS, 4) };
        restore_fixture(guard);
    }
}

//! `passkey_digit_complete` — `FUN_0827eb30` @ **0x0827eb30**.
//!
//! True extent: 196 bytes (192 code bytes and the literal at 0x0827ebf0),
//! ending at the next function's PUSH at 0x0827ebf4. Raw A32 decoding finds
//! seven outgoing plain BLs, zero predicated BLs; two inbound plain BLs at
//! 0x0813f92c and 0x0813ff44, zero predicated inbound BLs.
//!
//! Increment the signed selected-digit index below four. At four, state one
//! reconciles the entered passkey; other states compare confirmation and input.
//! A mismatch resets the index, assigns the shared payload to input and returns
//! four without refreshing. A match recovers state, copies confirmation to the
//! stored passkey, sets both state words to two, assigns the shared payload to
//! confirmation, then resets the index. All other active paths refresh the mask
//! indicators and reload state after that call. Indices >= four do nothing.
//!
//! Deliberate deviations: none on target. The unrecovered recovery callee retains
//! its exact address/ABI, not an invented identity. Tests substitute only callee
//! effects to exercise the state machine without placing native-width host
//! StringObjects at eight-byte-spaced target offsets. Shared payload is loaded
//! from runtime word 0x089cc12c; its contents are not inferred from file bytes.

use crate::cxx::string_object::{StringObject, string_object_assign,
    string_object_assign_cstr, string_object_equals};
use crate::app::controller_string_state_reconcile::controller_string_state_reconcile;
use crate::ui::passkey_mask_indicators::refresh_passkey_mask_indicators;

const STATE: usize = 0x68 / 4;
const INPUT: usize = 0x6c / 4;
const STORED: usize = 0x74 / 4;
const CONFIRMATION: usize = 0x7c / 4;
const DIGIT: usize = 0x8c / 4;
const NEXT_STATE: usize = 0x98 / 4;

// Static dispatch keeps the actual firmware path allocation-free and calls the
// existing ports directly. The test model owns the external callee effects.
trait Calls {
    unsafe fn reconcile(&mut self, owner: *mut u32) -> u32;
    unsafe fn matches(&mut self, owner: *mut u32) -> bool;
    unsafe fn recover(&mut self, owner: *mut u32) -> u32;
    unsafe fn store_confirmation(&mut self, owner: *mut u32);
    unsafe fn assign_shared(&mut self, owner: *mut u32, field: usize);
    unsafe fn refresh(&mut self, owner: *mut u32);
}

struct RetailCalls;
impl Calls for RetailCalls {
    unsafe fn reconcile(&mut self, owner: *mut u32) -> u32 {
        controller_string_state_reconcile(owner.cast(), 0)
    }
    unsafe fn matches(&mut self, owner: *mut u32) -> bool {
        string_object_equals(owner.add(CONFIRMATION).cast::<StringObject>(),
            owner.add(INPUT).cast::<StringObject>()) != 0
    }
    unsafe fn recover(&mut self, owner: *mut u32) -> u32 {
        #[cfg(target_os = "none")]
        {
            let call: unsafe extern "C" fn(*mut u8, u32) -> u32 =
                core::mem::transmute(0x0827_ef04usize);
            call(owner.cast(), 0)
        }
        #[cfg(not(target_os = "none"))]
        { let _ = owner; panic!("retailOS recovery requires the device"); }
    }
    unsafe fn store_confirmation(&mut self, owner: *mut u32) {
        string_object_assign(owner.add(STORED).cast(), owner.add(CONFIRMATION).cast());
    }
    unsafe fn assign_shared(&mut self, owner: *mut u32, field: usize) {
        let text = (0x089c_c12cusize as *const *const u8).read_volatile();
        string_object_assign_cstr(owner.add(field).cast(), text);
    }
    unsafe fn refresh(&mut self, owner: *mut u32) {
        refresh_passkey_mask_indicators(owner.cast());
    }
}

#[inline(always)]
unsafe fn complete(owner: *mut u32, calls: &mut impl Calls) -> u32 {
    let digit = owner.add(DIGIT).read_volatile() as i32;
    if digit < 4 {
        let digit = digit.wrapping_add(1);
        owner.add(DIGIT).write_volatile(digit as u32);
        if digit == 4 {
            if owner.add(STATE).read_volatile() == 1 {
                let state = calls.reconcile(owner);
                owner.add(STATE).write_volatile(state);
            } else {
                if !calls.matches(owner) {
                    owner.add(DIGIT).write_volatile(0);
                    calls.assign_shared(owner, INPUT);
                    return 4;
                }
                let state = calls.recover(owner);
                owner.add(STATE).write_volatile(state);
                calls.store_confirmation(owner);
                owner.add(NEXT_STATE).write_volatile(2);
                owner.add(STATE).write_volatile(2);
                calls.assign_shared(owner, CONFIRMATION);
            }
            owner.add(DIGIT).write_volatile(0);
        }
        calls.refresh(owner);
    }
    owner.add(STATE).read_volatile()
}

/// `owner` is an aligned target-layout object readable/writable through +0x98,
/// including its live vtable and embedded StringObjects. No NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn passkey_digit_complete(owner: *mut u32) -> u32 {
    complete(owner, &mut RetailCalls)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Model {
        input: &'static [u8],
        stored: &'static [u8],
        confirmation: &'static [u8],
        refresh_state: Option<u32>,
        refreshed: usize,
        recovered: bool,
        reconciled: bool,
    }
    impl Model {
        fn new() -> Self {
            Self { input: b"1234", stored: b"old", confirmation: b"1234",
                refresh_state: None, refreshed: 0, recovered: false, reconciled: false }
        }
    }
    impl Calls for Model {
        unsafe fn reconcile(&mut self, owner: *mut u32) -> u32 {
            assert_eq!(owner.add(DIGIT).read(), 4);
            self.reconciled = true;
            owner.add(DIGIT).write(99); // The caller must reset even after callee mutation.
            7
        }
        unsafe fn matches(&mut self, _: *mut u32) -> bool { self.input == self.confirmation }
        unsafe fn recover(&mut self, owner: *mut u32) -> u32 {
            assert_eq!(owner.add(DIGIT).read(), 4);
            self.recovered = true;
            9
        }
        unsafe fn store_confirmation(&mut self, owner: *mut u32) {
            assert_eq!(owner.add(STATE).read(), 9);
            self.stored = self.confirmation;
        }
        unsafe fn assign_shared(&mut self, owner: *mut u32, field: usize) {
            if field == INPUT {
                assert_eq!(owner.add(DIGIT).read(), 0);
                self.input = b"shared";
            } else {
                assert_eq!(field, CONFIRMATION);
                assert_eq!(owner.add(STATE).read(), 2);
                assert_eq!(owner.add(NEXT_STATE).read(), 2);
                self.confirmation = b"shared";
            }
        }
        unsafe fn refresh(&mut self, owner: *mut u32) {
            self.refreshed += 1;
            if let Some(state) = self.refresh_state { owner.add(STATE).write(state); }
        }
    }

    #[test]
    fn signed_boundaries_and_refresh_state_reload() {
        for digit in [i32::MIN, -1, 0, 1, 2, 4, 5, i32::MAX] {
            let mut owner = [0xa5a5a5a5; 40];
            owner[DIGIT] = digit as u32;
            owner[STATE] = 17;
            let before = owner;
            let mut model = Model::new();
            model.refresh_state = Some(23);
            let result = unsafe { complete(owner.as_mut_ptr(), &mut model) };
            let mut expected = before;
            if digit < 4 { expected[DIGIT] = digit.wrapping_add(1) as u32; expected[STATE] = 23; }
            assert_eq!(owner, expected);
            assert_eq!(result, expected[STATE]);
            assert_eq!(model.refreshed, usize::from(digit < 4));
            assert!(!model.recovered && !model.reconciled);
        }
    }

    #[test]
    fn mismatch_returns_four_without_refresh_or_stored_passkey_change() {
        let mut owner = [0xfeed; 40];
        owner[DIGIT] = 3;
        owner[STATE] = 0;
        let mut expected = owner;
        expected[DIGIT] = 0;
        let mut model = Model::new();
        model.confirmation = b"4321";
        assert_eq!(unsafe { complete(owner.as_mut_ptr(), &mut model) }, 4);
        assert_eq!(owner, expected);
        assert_eq!((model.input, model.stored, model.confirmation),
            (b"shared".as_slice(), b"old".as_slice(), b"4321".as_slice()));
        assert_eq!(model.refreshed, 0);
        assert!(!model.recovered && !model.reconciled);
    }

    #[test]
    fn confirmation_commits_passkey_before_reset_and_refresh() {
        for state in [0, 2, u32::MAX] {
            let mut owner = [0xfeed; 40];
            owner[DIGIT] = 3;
            owner[STATE] = state;
            let mut expected = owner;
            expected[DIGIT] = 0;
            expected[STATE] = 2;
            expected[NEXT_STATE] = 2;
            let mut model = Model::new();
            assert_eq!(unsafe { complete(owner.as_mut_ptr(), &mut model) }, 2);
            assert_eq!(owner, expected);
            assert_eq!((model.input, model.stored, model.confirmation),
                (b"1234".as_slice(), b"1234".as_slice(), b"shared".as_slice()));
            assert!(model.recovered && !model.reconciled);
            assert_eq!(model.refreshed, 1);
        }
    }

    #[test]
    fn state_one_reconciles_instead_of_committing_confirmation() {
        let mut owner = [0xfeed; 40];
        owner[DIGIT] = 3;
        owner[STATE] = 1;
        let mut expected = owner;
        expected[DIGIT] = 0;
        expected[STATE] = 7;
        let mut model = Model::new();
        assert_eq!(unsafe { complete(owner.as_mut_ptr(), &mut model) }, 7);
        assert_eq!(owner, expected);
        assert_eq!(model.stored, b"old");
        assert!(model.reconciled && !model.recovered);
        assert_eq!(model.refreshed, 1);
    }
}

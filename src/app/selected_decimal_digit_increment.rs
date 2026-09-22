//! `selected_decimal_digit_increment` — original: `FUN_0827f1a8` @ `0x0827f1a8`
//! (108 bytes: 104 bytes of code and the selector literal `0x53747220` at
//! `0x0827f214`).
//!
//! Verified from raw ARM words: two plain `bl` calls, zero predicated `bl`
//! calls, then one virtual `bx r3` tail call — three call sites total. It
//! chooses one of the owner's embedded StringObjects (`+0x6c`, or `+0xa4`
//! when word `+0xa0` is one), reads the codepoint at signed index `+0x8c`,
//! increments it, clears bit 16, and wraps values above ASCII `'9'` to `'0'`.
//! It passes the result to the retail mutation body at `0x08276840`, then
//! tail-dispatches vtable slot `+0x58` with selector `0x53747220` and
//! `index + 0x5795`.
//!
//! Deliberate deviation: the host build injects the two unported dispatches
//! and the already-ported codepoint read through one seam. The target build
//! calls `string_object_codepoint_at` directly and retains the two retail
//! function-pointer boundaries.

#[cfg(target_arch = "arm")]
use crate::cxx::string_object::{string_object_codepoint_at, StringObject};

const MODE_OFFSET: usize = 0xa0;
const ALTERNATE_STRING_OFFSET: usize = 0xa4;
const PRIMARY_STRING_OFFSET: usize = 0x6c;
const SELECTED_INDEX_OFFSET: usize = 0x8c;
const NOTIFY_SLOT_OFFSET: usize = 0x58;
const NOTIFY_SELECTOR: u32 = 0x5374_7220;
const NOTIFY_INDEX_BIAS: u32 = 0x5795;
const RETAIL_CODEPOINT_REPLACE: usize = 0x0827_6840;

pub type CodepointAt = unsafe extern "C" fn(*const u8, i32) -> u32;
pub type ReplaceCodepoint = unsafe extern "C" fn(*mut u8, i32, u32);
pub type SelectedDecimalDigitNotify = unsafe extern "C" fn(*mut u8, u32, u32);

#[derive(Clone, Copy)]
pub struct SelectedDecimalDigitIncrementOps {
    pub codepoint_at: CodepointAt,
    pub replace_codepoint: ReplaceCodepoint,
    pub notify: SelectedDecimalDigitNotify,
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_codepoint_at(_string: *const u8, _index: i32) -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_replace_codepoint(_string: *mut u8, _index: i32, _codepoint: u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_notify(_owner: *mut u8, _selector: u32, _index: u32) {}

#[cfg(not(target_arch = "arm"))]
pub const DEFAULT_SELECTED_DECIMAL_DIGIT_INCREMENT_OPS: SelectedDecimalDigitIncrementOps =
    SelectedDecimalDigitIncrementOps {
        codepoint_at: missing_codepoint_at,
        replace_codepoint: missing_replace_codepoint,
        notify: missing_notify,
    };

#[cfg(not(target_arch = "arm"))]
pub static mut SELECTED_DECIMAL_DIGIT_INCREMENT_OPS: SelectedDecimalDigitIncrementOps =
    DEFAULT_SELECTED_DECIMAL_DIGIT_INCREMENT_OPS;

#[inline(always)]
unsafe fn selected_string(owner: *mut u8) -> *mut u8 {
    if owner.add(MODE_OFFSET).cast::<u32>().read_volatile() == 1 {
        owner.add(ALTERNATE_STRING_OFFSET)
    } else {
        owner.add(PRIMARY_STRING_OFFSET)
    }
}

/// Increments the selected numeric character, replaces it, and notifies the
/// owning view. `owner` must have the target's readable word layout through
/// `+0xa4`; its selected embedded StringObject and callback target are not
/// NULL-checked by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_decimal_digit_increment(owner: *mut u8) {
    let index = owner.add(SELECTED_INDEX_OFFSET).cast::<i32>().read_volatile();
    let string = selected_string(owner);

    #[cfg(target_arch = "arm")]
    let codepoint = string_object_codepoint_at(string.cast::<StringObject>(), index);
    #[cfg(not(target_arch = "arm"))]
    let codepoint = (SELECTED_DECIMAL_DIGIT_INCREMENT_OPS.codepoint_at)(string, index);

    let next = codepoint.wrapping_add(1) & !0x0001_0000;
    let replacement = if next > b'9' as u32 { b'0' as u32 } else { next };

    #[cfg(target_arch = "arm")]
    {
        let replace: ReplaceCodepoint = core::mem::transmute(RETAIL_CODEPOINT_REPLACE);
        replace(string, index, replacement);
        let vtable = owner.cast::<u32>().read_volatile() as usize;
        let notify: SelectedDecimalDigitNotify = core::mem::transmute(
            ((vtable + NOTIFY_SLOT_OFFSET) as *const u32).read_volatile() as usize,
        );
        notify(owner, NOTIFY_SELECTOR, (index as u32).wrapping_add(NOTIFY_INDEX_BIAS));
    }
    #[cfg(not(target_arch = "arm"))]
    {
        (SELECTED_DECIMAL_DIGIT_INCREMENT_OPS.replace_codepoint)(string, index, replacement);
        (SELECTED_DECIMAL_DIGIT_INCREMENT_OPS.notify)(
            owner,
            NOTIFY_SELECTOR,
            (index as u32).wrapping_add(NOTIFY_INDEX_BIAS),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CODEPOINT: u32 = 0;
    static mut OBSERVED_STRING: usize = 0;
    static mut OBSERVED_REPLACEMENT: (i32, u32) = (0, 0);
    static mut OBSERVED_NOTIFICATION: (usize, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn codepoint_at(string: *const u8, _index: i32) -> u32 {
        OBSERVED_STRING = string as usize;
        CODEPOINT
    }
    unsafe extern "C" fn replace_codepoint(_string: *mut u8, index: i32, codepoint: u32) {
        OBSERVED_REPLACEMENT = (index, codepoint);
    }
    unsafe extern "C" fn notify(owner: *mut u8, selector: u32, index: u32) {
        OBSERVED_NOTIFICATION = (owner as usize, selector, index);
    }

    unsafe fn reset(codepoint: u32) {
        CODEPOINT = codepoint;
        OBSERVED_STRING = 0;
        OBSERVED_REPLACEMENT = (0, 0);
        OBSERVED_NOTIFICATION = (0, 0, 0);
        SELECTED_DECIMAL_DIGIT_INCREMENT_OPS = SelectedDecimalDigitIncrementOps {
            codepoint_at,
            replace_codepoint,
            notify,
        };
    }

    unsafe fn owner(mode: u32, index: i32) -> [u8; 0xa8] {
        let mut owner = [0u8; 0xa8];
        owner.as_mut_ptr().add(MODE_OFFSET).cast::<u32>().write_unaligned(mode);
        owner.as_mut_ptr().add(SELECTED_INDEX_OFFSET).cast::<i32>().write_unaligned(index);
        owner
    }

    #[test]
    fn increments_primary_digit_and_notifies() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset(b'8' as u32);
            let mut owner = owner(0, 4);
            selected_decimal_digit_increment(owner.as_mut_ptr());
            assert_eq!(OBSERVED_STRING, owner.as_mut_ptr().add(PRIMARY_STRING_OFFSET) as usize);
            assert_eq!(OBSERVED_REPLACEMENT, (4, b'9' as u32));
            assert_eq!(OBSERVED_NOTIFICATION, (owner.as_mut_ptr() as usize, NOTIFY_SELECTOR, 0x5799));
        }
    }

    #[test]
    fn wraps_nine_and_uses_alternate_string() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset(b'9' as u32);
            let mut owner = owner(1, -1);
            selected_decimal_digit_increment(owner.as_mut_ptr());
            assert_eq!(OBSERVED_STRING, owner.as_mut_ptr().add(ALTERNATE_STRING_OFFSET) as usize);
            assert_eq!(OBSERVED_REPLACEMENT, (-1, b'0' as u32));
            assert_eq!(OBSERVED_NOTIFICATION.2, 0x5794);
        }
    }

    #[test]
    fn bit_sixteen_is_cleared_before_range_test() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset(0xffff);
            let mut owner = owner(2, i32::MAX);
            selected_decimal_digit_increment(owner.as_mut_ptr());
            assert_eq!(OBSERVED_REPLACEMENT, (i32::MAX, 0));
            assert_eq!(OBSERVED_NOTIFICATION.2, 0x8000_5794);
        }
    }
}

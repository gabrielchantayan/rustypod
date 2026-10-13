//! Callback visitation of an aligned half-open word range.

pub type WordVisitor = unsafe extern "C" fn(u32);

/// retailOS `FUN_083eaab0` at **0x083eaab0**, **48 bytes**
/// ([0x083eaab0, 0x083eaae0), next entry begins with PUSH {r3, lr}).
/// Whole-image aligned raw A32 decoding finds one incoming plain BL at
/// 0x08168544, zero predicated BLs, and one tail B at 0x08168688.
/// The body contains zero plain/predicated BLs and one indirect BLX r6.
///
/// Snapshot begin, end, and callback; load each aligned u32 in order,
/// invoke the callback with its value, and advance by four until pointer
/// equality with end. Return the original callback, even for an empty range.
/// Callback writes to not-yet-visited words are observed by subsequent loads.
///
/// Deliberate deviations: none for ABI-conforming callbacks. The callback's
/// return register is ignored, represented by a void callback signature.
/// No identity is assumed for callers' callback literals; the separately
/// deferred interior entry at 0x0815d7c4 is not a supported C ABI callback.
///
/// # Safety
/// Unless begin == end, the bounds must describe one aligned readable u32
/// allocation, with end reachable by forward word steps. Callback must obey
/// the C ABI and leave remaining words readable for the duration of the loop.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn visit_word_range_return_callback(
    mut begin: *const u32,
    end: *const u32,
    callback: WordVisitor,
) -> WordVisitor {
    while begin != end {
        callback(begin.read());
        begin = begin.add(1);
    }
    callback
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::vec::Vec;

    std::thread_local! {
        static SEEN: RefCell<Vec<u32>> = RefCell::new(Vec::new());
        static REWRITE: Cell<*mut u32> = Cell::new(core::ptr::null_mut());
    }

    unsafe extern "C" fn record(value: u32) {
        SEEN.with(|seen| seen.borrow_mut().push(value));
        REWRITE.with(|slot| {
            let next = slot.replace(core::ptr::null_mut());
            if !next.is_null() { next.write(0xdead_beef); }
        });
    }

    #[test]
    fn all_subranges_preserve_order_values_and_callback() {
        let words = [0, u32::MAX, 0x8000_0000, 7, 7, 0x1234_5678];
        for start in 0..=words.len() {
            for end in start..=words.len() {
                SEEN.with(|seen| seen.borrow_mut().clear());
                let returned = unsafe {
                    visit_word_range_return_callback(words.as_ptr().add(start),
                        words.as_ptr().add(end), record)
                };
                assert_eq!(returned as usize, record as WordVisitor as usize);
                SEEN.with(|seen| assert_eq!(&*seen.borrow(), &words[start..end]));
            }
        }
    }

    #[test]
    fn empty_invalid_bounds_are_not_read() {
        for bound in [core::ptr::null(), 1usize as *const u32] {
            SEEN.with(|seen| seen.borrow_mut().clear());
            let returned = unsafe { visit_word_range_return_callback(bound, bound, record) };
            assert_eq!(returned as usize, record as WordVisitor as usize);
            SEEN.with(|seen| assert!(seen.borrow().is_empty()));
        }
    }

    #[test]
    fn callback_mutation_is_loaded_on_next_iteration() {
        let mut words = [1, 2, 3];
        SEEN.with(|seen| seen.borrow_mut().clear());
        let begin = words.as_mut_ptr();
        REWRITE.with(|slot| slot.set(unsafe { begin.add(1) }));
        unsafe { visit_word_range_return_callback(begin, begin.add(3), record); }
        SEEN.with(|seen| assert_eq!(&*seen.borrow(), &[1, 0xdead_beef, 3]));
        assert_eq!(words, [1, 0xdead_beef, 3]);
    }
}

//! Converts an optional canonical-composed counted UTF-16 buffer to UTF-8.
//!
//! `counted_utf16_to_utf8` — original: `FUN_081131a8` @ **0x081131a8**
//! (88 bytes, `0x081131a8..0x081131ff`). The next real function begins with
//! `push {r4, lr}` at 0x08113200. It has **3 direct plain `bl` call sites**
//! (0x081127c0, 0x0811282c, and 0x08115988) and zero predicated direct `bl`
//! call sites, verified by decoding every A32 branch word in `osos.dec`.
//!
//! The input begins with its u16 code-unit count, followed by that many UTF-16
//! units. An empty count writes one NUL byte. Otherwise a nonzero
//! `compose_canonically` first invokes `FUN_081113d8`, which repeatedly asks
//! the Unicode composition table at `FUN_0809330c` to merge adjacent units and
//! updates the count in place. The resulting counted range is sized and
//! encoded by the ported bounded UTF-16 helpers, then this wrapper overwrites
//! the last allocated byte with NUL.
//!
//! Deliberate deviation: `FUN_081113d8` is identified but not ported. ARM
//! builds call its stock entry directly; host builds use the injectable
//! [`COUNTED_UTF16_CANONICAL_COMPOSE`] boundary. The `unused` ABI argument is
//! not read by the original and is deliberately ignored.

use crate::cxx::string_encoding::utf16_to_utf8_bounded;
use crate::cxx::string_object::utf16_utf8_byte_len_bounded_plus1;

pub type CountedUtf16CanonicalComposeFn = unsafe extern "C" fn(*mut u16);

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn compose_counted_utf16(text: *mut u16) {
    let compose: CountedUtf16CanonicalComposeFn = core::mem::transmute(0x0811_13d8usize);
    compose(text);
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_counted_utf16_canonical_compose(_: *mut u16) {}

/// Host boundary for the identified-but-unported `FUN_081113d8` canonical
/// composition worker. The default preserves its call boundary but cannot
/// compose until that worker is ported.
#[cfg(not(target_arch = "arm"))]
pub static mut COUNTED_UTF16_CANONICAL_COMPOSE: CountedUtf16CanonicalComposeFn =
    missing_counted_utf16_canonical_compose;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn compose_counted_utf16(text: *mut u16) {
    (core::ptr::read_volatile(core::ptr::addr_of!(COUNTED_UTF16_CANONICAL_COMPOSE)))(text);
}

/// counted_utf16_to_utf8 — original: `FUN_081131a8` @ 0x081131a8 (88 bytes;
/// 3 plain direct `bl` callers, zero predicated).
///
/// `text[0]` is a u16 code-unit count and `text[1..]` is its UTF-16 payload.
/// An empty count stores a NUL in `out`. A nonempty count optionally composes
/// the counted payload in place, encodes no more than the resulting count, and
/// forces the final allocated byte to NUL. `unused` is passed in r2 but never
/// read by the ARM body.
///
/// # Safety
/// `text` must be writable through its declared count when composition is
/// requested and readable otherwise. `out` must hold the inclusive UTF-8 size
/// implied by the counted range.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_utf16_to_utf8(
    text: *mut u16,
    out: *mut u8,
    _unused: u32,
    compose_canonically: i32,
) {
    if text.read() == 0 {
        out.write(0);
        return;
    }
    if compose_canonically != 0 {
        compose_counted_utf16(text);
    }
    let count = i32::from(text.read());
    let source = text.add(1);
    let byte_len = utf16_utf8_byte_len_bounded_plus1(source, count);
    utf16_to_utf8_bounded(out, source, count);
    out.offset(byte_len.wrapping_sub(1) as isize).write(0);
}

#[cfg(test)]
mod tests {
    use super::{counted_utf16_to_utf8, CountedUtf16CanonicalComposeFn, COUNTED_UTF16_CANONICAL_COMPOSE};
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut COMPOSE_CALLS: u32 = 0;

    unsafe extern "C" fn compose_first_pair(text: *mut u16) {
        COMPOSE_CALLS += 1;
        assert_eq!(text.read(), 2);
        text.add(1).write(0x00e9);
        text.write(1);
    }

    struct ComposeReset(CountedUtf16CanonicalComposeFn);
    impl Drop for ComposeReset {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(COUNTED_UTF16_CANONICAL_COMPOSE), self.0) };
        }
    }

    unsafe fn install_compose(compose: CountedUtf16CanonicalComposeFn) -> ComposeReset {
        ComposeReset(ptr::read_volatile(ptr::addr_of!(COUNTED_UTF16_CANONICAL_COMPOSE))).tap(|_| {
            ptr::write_volatile(ptr::addr_of_mut!(COUNTED_UTF16_CANONICAL_COMPOSE), compose);
        })
    }

    trait Tap: Sized { fn tap(self, f: impl FnOnce(&Self)) -> Self; }
    impl<T> Tap for T { fn tap(self, f: impl FnOnce(&Self)) -> Self { f(&self); self } }

    #[test]
    fn empty_count_writes_only_the_terminator() {
        let _lock = TEST_LOCK.lock();
        let mut text = [0u16];
        let mut out = [0xa5u8, 0x5a];
        unsafe { counted_utf16_to_utf8(text.as_mut_ptr(), out.as_mut_ptr(), 0xdead_beef, 0) };
        assert_eq!(out, [0, 0x5a]);
    }

    #[test]
    fn bounded_encoding_stops_at_embedded_nul_and_terminates() {
        let _lock = TEST_LOCK.lock();
        let mut text = [3u16, b'A' as u16, 0, b'B' as u16];
        let mut out = [0xa5u8; 5];
        unsafe { counted_utf16_to_utf8(text.as_mut_ptr(), out.as_mut_ptr(), 0, 0) };
        assert_eq!(out, [b'A', 0, 0xa5, 0xa5, 0xa5]);
    }

    #[test]
    fn composition_updates_the_count_before_sizing_and_encoding() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            COMPOSE_CALLS = 0;
            let _reset = install_compose(compose_first_pair);
            let mut text = [2u16, b'e' as u16, 0x0301];
            let mut out = [0xa5u8; 4];
            counted_utf16_to_utf8(text.as_mut_ptr(), out.as_mut_ptr(), 0, 1);
            assert_eq!(COMPOSE_CALLS, 1);
            assert_eq!(text[0], 1);
            assert_eq!(out, [0xc3, 0xa9, 0, 0xa5]);
        }
    }
}

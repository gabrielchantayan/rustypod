//! Observable-array-bearing view constructor: `FUN_081bb0ec` @ `0x081bb0ec`.
//!
//! True extent: 48 bytes, 44 executable bytes and vtable literal at
//! `0x081bb118`, before the next function at `0x081bb11c`. Raw words verify
//! two plain BL instructions and zero predicated BL; whole-image decoding
//! finds two inbound plain BL sites (`0x081852b0`, `0x081bab54`).
//!
//! Forwards this and four opaque inherited arguments to `0x08288d38`,
//! installs vtable `0x0898c854` on its returned pointer, constructs the
//! observable array at +0x1e0, and returns that constructor's result minus
//! 0x1e0. The factory allocates 0x1f0 bytes. The class's domain identity and
//! inherited argument meanings are not recovered; the name describes layout.
//!
//! Deliberate deviation: host execution injects the unported inherited
//! constructor; target execution calls its verified firmware address. No
//! inherited initialization is approximated. All offsets stay target-width.

use crate::cxx::observable_array::{observable_array_construct, ObservableArray};

pub const OBSERVABLE_ARRAY_VIEW_VTABLE: u32 = 0x0898_c854;
type InheritedConstruct = unsafe extern "C" fn(*mut u8, u32, u32, u32, u32) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_inherited_construct(_: *mut u8, _: u32, _: u32, _: u32, _: u32) -> *mut u8 {
    panic!("install observable-array view inherited constructor host seam")
}

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_VIEW_INHERITED_CONSTRUCT: InheritedConstruct = unavailable_inherited_construct;

/// Construct the inherited view and its embedded empty observable array.
///
/// # Safety
/// The inherited constructor must accept the four unchanged argument words
/// and return a four-byte-aligned writable object of at least 0x1f0 bytes.
/// Its own input validity requirements also apply. Host callers must install
/// the inherited-constructor seam and serialize access to it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_view_construct(
    this: *mut u8,
    inherited_first: u32,
    inherited_second: u32,
    inherited_third: u32,
    inherited_fourth: u32,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    let construct = core::mem::transmute::<usize, InheritedConstruct>(0x0828_8d38);
    #[cfg(not(target_os = "none"))]
    let construct = core::ptr::addr_of!(OBSERVABLE_ARRAY_VIEW_INHERITED_CONSTRUCT).read_volatile();
    let base = construct(this, inherited_first, inherited_second, inherited_third, inherited_fourth);
    base.cast::<u32>().write_volatile(OBSERVABLE_ARRAY_VIEW_VTABLE);
    let array = observable_array_construct(base.add(0x1e0).cast::<ObservableArray>());
    array.cast::<u8>().sub(0x1e0)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    // Redirect to a distinct object: stores must follow the inherited return,
    // not the input pointer. Populate the prefix as inherited initialization.
    unsafe extern "C" fn redirect(this: *mut u8, _: u32, _: u32, _: u32, _: u32) -> *mut u8 {
        let base = this.add(0x1f0);
        base.cast::<u32>().add(1).write(0x1234_5678);
        base
    }

    #[test]
    fn initializes_only_derived_fields_on_inherited_return() {
        let _guard = LOCK.lock();
        let mut words = [0xa5a5_a5a5u32; 0x3f0 / 4];
        unsafe {
            let previous = OBSERVABLE_ARRAY_VIEW_INHERITED_CONSTRUCT;
            OBSERVABLE_ARRAY_VIEW_INHERITED_CONSTRUCT = redirect;
            let input = words.as_mut_ptr().cast::<u8>();
            let result = observable_array_view_construct(input, 0, u32::MAX, 0x8000_0000, 7);
            OBSERVABLE_ARRAY_VIEW_INHERITED_CONSTRUCT = previous;
            assert_eq!(result, input.add(0x1f0));
        }
        let base = 0x1f0 / 4;
        assert_eq!(words[base], OBSERVABLE_ARRAY_VIEW_VTABLE);
        assert_eq!(words[base + 1], 0x1234_5678);
        assert_eq!(words[base + 0x1e0 / 4], OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(&words[base + 0x1e4 / 4..base + 0x1f0 / 4], &[0, 0, 0]);
        assert!(words[..base].iter().all(|&word| word == 0xa5a5_a5a5));
        assert!(words[base + 2..base + 0x1e0 / 4].iter().all(|&word| word == 0xa5a5_a5a5));
        assert_eq!(&words[base + 0x1f0 / 4..], &[0xa5a5_a5a5; 4]);
    }
}

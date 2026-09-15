//! `opaque_layout_construct` — original: `FUN_08261da8` @ **0x08261da8**
//! (20 bytes, 0x08261da8..0x08261dbc).
//!
//! Raw words `e92d4010 e1a04000 eb02178e e1a00004 e8bd8010` establish the
//! complete body: preserve `this` in r4, call the 40-byte layout initializer
//! at 0x082e7bf0, then return `this`. The `push {r4,lr}` at 0x08261dbc starts
//! the next separately linked function. Decoding the inbound branch words
//! finds five plain unconditional `bl` call sites (0x081e6b70, 0x0826287c,
//! 0x0839e898, 0x0839ea04, and 0x0839f3e0) and no predicated `bl` call sites.
//!
//! Algorithm: initialize the opaque 40-byte layout record through its existing
//! retailOS initializer, discard that initializer's status result, and return
//! the original record pointer. Deliberate deviation: the initializer is not
//! yet ported, so target builds call its fixed address through a function
//! pointer and host builds expose a volatile callback seam. This preserves the
//! verified pointer and return-value contract, but lowers the target call as
//! an indirect `blx` instead of the stock direct `bl`.

#[cfg(not(target_os = "none"))]
use core::ptr;

const RETAIL_OPAQUE_LAYOUT_INITIALIZE: usize = 0x082e_7bf0;

type OpaqueLayoutInitialize = unsafe extern "C" fn(*mut u8) -> u32;

/// Host callback seam for the unported initializer at 0x082e7bf0.
#[cfg(not(target_os = "none"))]
pub struct OpaqueLayoutConstructOps {
    pub initialize: OpaqueLayoutInitialize,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_layout_initialize(_layout: *mut u8) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_LAYOUT_CONSTRUCT_OPS: OpaqueLayoutConstructOps = OpaqueLayoutConstructOps {
    initialize: missing_opaque_layout_initialize,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn opaque_layout_initialize(layout: *mut u8) -> u32 {
    let initialize: OpaqueLayoutInitialize = core::mem::transmute(RETAIL_OPAQUE_LAYOUT_INITIALIZE);
    initialize(layout)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn opaque_layout_initialize(layout: *mut u8) -> u32 {
    let initialize = ptr::read_volatile(ptr::addr_of!(OPAQUE_LAYOUT_CONSTRUCT_OPS.initialize));
    initialize(layout)
}

/// Initializes `layout` through retailOS's 40-byte layout initializer and
/// returns `layout`, including when it is null.
///
/// # Safety
/// `layout` must meet the initializer at 0x082e7bf0's requirements. The stock
/// wrapper does not validate it and still forwards null.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_layout_construct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_layout_construct(layout: *mut u8) -> *mut u8 {
    opaque_layout_initialize(layout);
    layout
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static INITIALIZE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static INITIALIZE_LAYOUT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_initialize(layout: *mut u8) -> u32 {
        INITIALIZE_LAYOUT.store(layout as usize, Ordering::SeqCst);
        INITIALIZE_CALLS.fetch_add(1, Ordering::SeqCst);
        0x1a
    }

    fn install_recording_initializer() {
        unsafe {
            OPAQUE_LAYOUT_CONSTRUCT_OPS.initialize = record_initialize;
        }
        INITIALIZE_CALLS.store(0, Ordering::SeqCst);
        INITIALIZE_LAYOUT.store(usize::MAX, Ordering::SeqCst);
    }

    #[test]
    fn forwards_a_live_layout_once_and_returns_its_original_pointer() {
        let _guard = TEST_LOCK.lock();
        let mut layout = [0xa5_u8; 40];
        install_recording_initializer();

        let result = unsafe { opaque_layout_construct(layout.as_mut_ptr()) };

        assert_eq!(result, layout.as_mut_ptr());
        assert_eq!(INITIALIZE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(INITIALIZE_LAYOUT.load(Ordering::SeqCst), layout.as_mut_ptr() as usize);
        assert_eq!(layout, [0xa5; 40], "the wrapper itself writes no layout bytes");
    }

    #[test]
    fn forwards_null_and_returns_null_despite_the_initializers_status() {
        let _guard = TEST_LOCK.lock();
        install_recording_initializer();

        let result = unsafe { opaque_layout_construct(core::ptr::null_mut()) };

        assert!(result.is_null());
        assert_eq!(INITIALIZE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(INITIALIZE_LAYOUT.load(Ordering::SeqCst), 0);
    }
}

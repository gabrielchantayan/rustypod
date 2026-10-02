//! Resolve-gated teardown of a UI element reference's subject.
//!
//! Original: FUN_08284044 @ 0x08284044, true size 56 bytes through the
//! pop at 0x08284078; the next real function starts at 0x0828407c.
//! Raw whole-image ARM-word scan: one plain inbound BL (0x08179a20), one
//! predicated BLNE (0x0816f06c). Body: one plain BL, zero predicated BLs,
//! and one indirect BLX through reference vtable slot +0x0c.
//!
//! Resolve the reference; zero leaves its subject unchanged. Any nonzero
//! result tears down the post-resolve subject through 0x080491dc with a
//! zero second argument, then clears the subject word. The callee recursively
//! tears down an element hierarchy; its precise class identity is unresolved.
//! Both addresses were absent from names.yaml before this port.
//! Target deviations: none. Host uses a native-width virtual function slot
//! and a replaceable teardown seam; reference fields retain u32 width.

const SUBJECT_WORD: usize = 1;
const RESOLVE_OFFSET: usize = 0x0c;
type Resolve = unsafe extern "C" fn(*mut u32) -> u32;
type Teardown = unsafe extern "C" fn(u32, u32);

#[cfg(not(target_os = "none"))]
static mut SUBJECT_TEARDOWN: Teardown = unavailable_teardown;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_teardown(_: u32, _: u32) {
    panic!("firmware subject teardown requires a host implementation");
}

#[inline(always)]
unsafe fn subject_teardown(subject: u32) {
    #[cfg(target_os = "none")]
    let teardown: Teardown = core::mem::transmute(0x0804_91dcusize);
    #[cfg(not(target_os = "none"))]
    let teardown = SUBJECT_TEARDOWN;
    teardown(subject, 0);
}

/// Tear down and clear the resolved subject; failed resolve does not clear it.
///
/// # Safety
/// `reference` must be word-aligned, writable through its subject at +4,
/// and hold a valid vtable with a callable resolve slot at +0x0c. On successful
/// resolve the updated subject must satisfy firmware 0x080491dc's contract.
/// Host callers must supply the teardown seam before successful resolution.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_reference_teardown(reference: *mut u32) {
    let vtable = reference.read() as usize as *const u8;
    #[cfg(target_os = "none")]
    let resolve = vtable.add(RESOLVE_OFFSET).cast::<Resolve>().read();
    #[cfg(not(target_os = "none"))]
    let resolve = vtable.add(RESOLVE_OFFSET).cast::<Resolve>().read_unaligned();
    if resolve(reference) == 0 {
        return;
    }
    subject_teardown(reference.add(SUBJECT_WORD).read());
    reference.add(SUBJECT_WORD).write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{LazyLock, Mutex};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVE_RESULT: u32 = 0;
    static mut REPLACEMENT: u32 = 0;
    static mut ACTIVE_REFERENCE: *mut u32 = core::ptr::null_mut();
    static mut EXPECTED_SUBJECT: u32 = 0;
    static mut TEARDOWNS: u32 = 0;

    unsafe extern "C" fn resolve(reference: *mut u32) -> u32 {
        assert_eq!(reference, ACTIVE_REFERENCE);
        reference.add(SUBJECT_WORD).write(REPLACEMENT);
        RESOLVE_RESULT
    }

    unsafe extern "C" fn teardown(subject: u32, flag: u32) {
        assert_eq!(subject, EXPECTED_SUBJECT);
        assert_eq!(flag, 0);
        // Clearing before teardown would lose the subject seen by callbacks.
        assert_eq!(ACTIVE_REFERENCE.add(SUBJECT_WORD).read(), subject);
        ACTIVE_REFERENCE.add(SUBJECT_WORD).write(0xdead_beef);
        TEARDOWNS += 1;
    }

    #[test]
    fn resolve_failure_preserves_state_and_success_clears_after_teardown() {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(
                crate::testing::hints::ELEMENT_REFERENCE_TEARDOWN, 0x1000,
            ).map(|p| p as usize)
        });
        let Some(base) = *SLAB else {
            crate::testing::note_missing_u32_fixture("ui::element_reference_teardown");
            return;
        };
        unsafe {
            let reference = base as *mut u32;
            let vtable = (base as *mut u8).add(0x100);
            reference.write(vtable as u32);
            reference.add(2).write(0xa5a5_1234);
            vtable.add(RESOLVE_OFFSET).cast::<Resolve>().write_unaligned(resolve);
            ACTIVE_REFERENCE = reference;
            SUBJECT_TEARDOWN = teardown;
            RESOLVE_RESULT = 0;
            REPLACEMENT = 1; // An invalid subject must never reach teardown.
            TEARDOWNS = 0;
            ui_element_reference_teardown(reference);
            assert_eq!(reference.add(1).read(), 1);
            assert_eq!(TEARDOWNS, 0);
            for result in [1, 0x8000_0000, u32::MAX] {
                for subject in [0, 0x1234_5678, u32::MAX] {
                    reference.add(1).write(0x1122_3344);
                    RESOLVE_RESULT = result;
                    REPLACEMENT = subject;
                    EXPECTED_SUBJECT = subject;
                    ui_element_reference_teardown(reference);
                    assert_eq!(reference.add(1).read(), 0);
                    assert_eq!(reference.read(), vtable as u32);
                    assert_eq!(reference.add(2).read(), 0xa5a5_1234);
                }
            }
            assert_eq!(TEARDOWNS, 9);
            SUBJECT_TEARDOWN = unavailable_teardown;
        }
    }
}

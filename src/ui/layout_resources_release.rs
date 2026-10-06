//! Release a layout owner's objects and auxiliary allocation.
//!
//! Original: FUN_0816ba38 @ 0x0816ba38, 40 bytes; next function starts
//! at 0x0816ba60. Raw ARM words verify two plain internal BLs and zero
//! predicated BLs; inbound calls are two plain BLs, zero predicated BLs.
//! Call object teardown @ 0x0816b318, then reload the target-width pointer
//! at +0xec. If nonzero, delete with tag 3 and clear it after deletion.
//! The teardown releases the objects at +0x114 and +0x110; the precise
//! layout class is unresolved. Deviations: use the existing Rust tag-3
//! delete port; the unported object teardown remains a firmware call.
//! Hosts supply that teardown seam; all owner fields retain u32 width.

const ALLOCATION_WORD: usize = 0xec / 4;
type ObjectTeardown = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
static mut OBJECT_TEARDOWN: ObjectTeardown = unavailable_teardown;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_teardown(_: *mut u32) {
    panic!("layout object teardown requires a host implementation");
}

/// Release owned objects before deleting the auxiliary allocation.
///
/// # Safety
/// `owner` must be aligned, writable through +0x114, and satisfy the
/// object teardown's ownership/vtable contracts. Its post-teardown +0xec
/// word must be zero or a valid tag-3 allocation. Hosts must install the seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_layout_resources_release(owner: *mut u32) {
    #[cfg(target_os = "none")]
    let teardown: ObjectTeardown = core::mem::transmute(0x0816_b318usize);
    #[cfg(not(target_os = "none"))]
    let teardown = OBJECT_TEARDOWN;
    teardown(owner);
    let allocation = owner.add(ALLOCATION_WORD).read();
    if allocation != 0 {
        crate::heap::veneers::operator_delete_tag3(allocation as usize as *mut u8);
        owner.add(ALLOCATION_WORD).write(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static mut REPLACEMENT: u32 = 0;
    static mut TEARDOWNS: usize = 0;

    unsafe extern "C" fn teardown(owner: *mut u32) {
        TEARDOWNS += 1;
        owner.add(ALLOCATION_WORD).write(REPLACEMENT);
    }

    #[test]
    fn reloads_after_teardown_and_handles_repeated_release() {
        let _lock = crate::heap::veneers::tests::mock_heap();
        unsafe {
            let saved = OBJECT_TEARDOWN;
            OBJECT_TEARDOWN = teardown;
            TEARDOWNS = 0;
            let mut owner = [0xa5a5_1234u32; 0x118 / 4];
            let mut frees = 0;
            for (before, after) in [(0, 0), (0x1234, 0), (0, 0x8123_4560),
                                    (0x1234, 0xffff_fffc), (0, 0)] {
                owner[ALLOCATION_WORD] = before;
                REPLACEMENT = after;
                ui_layout_resources_release(owner.as_mut_ptr());
                assert_eq!(owner[ALLOCATION_WORD], 0);
                if after != 0 {
                    frees += 1;
                    assert_eq!(crate::heap::veneers::tests::free_log(),
                               (frees, after as usize as *mut u8, 3));
                } else {
                    assert_eq!(crate::heap::veneers::tests::free_log().0, frees);
                }
                for (index, word) in owner.iter().enumerate() {
                    if index != ALLOCATION_WORD { assert_eq!(*word, 0xa5a5_1234); }
                }
            }
            assert_eq!(TEARDOWNS, 5);
            OBJECT_TEARDOWN = saved;
        }
    }
}

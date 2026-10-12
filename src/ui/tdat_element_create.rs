//! `tdat_element_create` — FUN_08047bfc @ 0x08047bfc.
//! True extent [0x08047bfc,0x08047cc8): 204 bytes (188 code + 16 literals).
//! The next word is the independently called leaf-tag-mask veneer. Raw A32
//! scan: two plain inbound BLs (0x08058974,0x08068f2c), eight plain outbound
//! BLs, zero predicated BLs in either direction.
//!
//! Allocate 0x948 zeroed bytes, stamp 'tdat', owner, payload, sequence and
//! default callback, then append to the owner's list before initialization.
//! Initialize the two embedded records, link the receiver to the owner's
//! sender, then initialize track caches/resources. Stop at the first error,
//! destroy the partially initialized element, and publish NULL. Allocation
//! failure returns -108 without touching output; NULL output is accepted.
//!
//! Deliberate deviations: seven callees reuse Rust ports. The unported
//! cache/resource initializer at 0x080d25d4 remains a resident target call;
//! its raw code initializes named TrackData caches and two FixA owners.
//! Host tests inject dependencies into the same allocation/state algorithm.

use core::ptr;
use crate::heap::veneers::calloc_tag4;
use crate::util::singly_linked_list_append::singly_linked_list_append;
use crate::util::opaque_52_byte_record_initialize::opaque_52_byte_record_initialize;
use crate::util::opaque_56_byte_record_initialize::opaque_56_byte_record_initialize;
use super::object_state::sequence_id_next;
use super::tagged_object_link::tagged_object_link;
use super::tdat_destroy::tdat_element_destroy;

unsafe fn initialize_track_resources(element: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    {
        let call: unsafe extern "C" fn(*mut u8) -> i32 = core::mem::transmute(0x080d_25d4usize);
        call(element)
    }
    #[cfg(not(target_os = "none"))]
    { let _ = element; panic!("tdat resource initialization requires retailOS"); }
}

/// # Safety
/// Owner must be aligned and contain a valid list at +0xb98 and sender at
/// +0xbac. A non-NULL output must be writable for one target-width word.
/// The heap, sequence state, and resident initialization must be available.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tdat_element_create(owner: *mut u8, payload: u32, output: *mut u32) -> i32 {
    create(owner, payload, output, || calloc_tag4(0x948), || sequence_id_next(),
        |stage, element| match stage {
            0 => opaque_52_byte_record_initialize(element.add(0x54)),
            1 => opaque_56_byte_record_initialize(element.add(0x88), 0x080c_1368, element as usize as u32),
            2 => tagged_object_link(owner.add(0xbac).cast(), element.add(0x88).cast()),
            _ => initialize_track_resources(element),
        }, |element| tdat_element_destroy(element))
}

#[inline(always)]
unsafe fn create(
    owner: *mut u8, payload: u32, output: *mut u32,
    allocate: impl FnOnce() -> *mut u8, sequence: impl FnOnce() -> u32,
    mut initialize: impl FnMut(usize, *mut u8) -> i32,
    mut destroy: impl FnMut(*mut u8),
) -> i32 {
    let mut element = allocate();
    if element.is_null() { return -108; }
    element.add(4).cast::<u32>().write(0x7464_6174);
    element.add(8).cast::<u32>().write(owner as usize as u32);
    element.add(0x18).cast::<u32>().write(sequence());
    element.add(0x4c).cast::<u32>().write(0x080d_adc8);
    element.add(0x0c).cast::<u32>().write(payload);
    singly_linked_list_append(owner.add(0xb98).cast(), element.cast());
    let mut status = 0;
    for stage in 0..4 {
        status = initialize(stage, element);
        if status != 0 {
            destroy(element);
            element = ptr::null_mut();
            break;
        }
    }
    if !output.is_null() { output.write(element as usize as u32); }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use crate::util::singly_linked_list_remove::singly_linked_list_remove;

    #[test]
    fn allocation_failure_preserves_output_and_never_initializes() {
        let mut output = 0xdead_beef;
        let status = unsafe { create(ptr::null_mut(), 9, &mut output,
            || ptr::null_mut(), || panic!("sequence on OOM"),
            |_, _| panic!("initialize on OOM"), |_| panic!("destroy on OOM")) };
        assert_eq!(status, -108);
        assert_eq!(output, 0xdead_beef);
    }

    #[test]
    fn publishes_only_success_and_rolls_back_each_initialization_failure() {
        let Some(base) = try_map_u32_slab(hints::TDAT_ELEMENT_CREATE, 0x4000) else { return; };
        unsafe {
            let owner = base.cast::<u8>();
            let element = owner.add(0x1000);
            let previous = owner.add(0x2000).cast::<u32>();
            for failure in 0..=4 {
                for null_output in [false, true] {
                    ptr::write_bytes(owner, 0, 0x4000);
                    owner.add(0xb98).cast::<u32>().write(previous as usize as u32);
                    let mut output = 0xdead_beef;
                    let output_ptr = ptr::addr_of_mut!(output);
                    let mut stages = std::vec::Vec::new();
                    let mut destroyed = false;
                    let status = create(owner, 0x1234_5678,
                        if null_output { ptr::null_mut() } else { output_ptr },
                        || element, || u32::MAX,
                        |stage, object| {
                            assert_eq!(object, element);
                            assert_eq!(output, 0xdead_beef);
                            assert_eq!(previous.read(), element as usize as u32);
                            assert_eq!(object.cast::<u32>().read(), 0);
                            assert_eq!(object.add(4).cast::<u32>().read(), 0x7464_6174);
                            assert_eq!(object.add(8).cast::<u32>().read(), owner as usize as u32);
                            assert_eq!(object.add(12).cast::<u32>().read(), 0x1234_5678);
                            assert_eq!(object.add(0x18).cast::<u32>().read(), u32::MAX);
                            assert_eq!(object.add(0x4c).cast::<u32>().read(), 0x080d_adc8);
                            stages.push(stage);
                            if stage == failure { -71 } else { 0 }
                        }, |object| {
                            destroyed = true;
                            singly_linked_list_remove(owner.add(0xb98).cast(), object.cast());
                            ptr::write_bytes(object, 0, 0x948);
                        });
                    assert_eq!(stages, (0..core::cmp::min(failure + 1, 4)).collect::<std::vec::Vec<_>>());
                    assert_eq!(status, if failure < 4 { -71 } else { 0 });
                    assert_eq!(destroyed, failure < 4);
                    assert_eq!(previous.read(), if failure < 4 { 0 } else { element as usize as u32 });
                    assert_eq!(owner.add(0xb98).cast::<u32>().read(), previous as usize as u32);
                    assert_eq!(output, if null_output { 0xdead_beef } else if failure < 4 { 0 } else { element as usize as u32 });
                }
            }
        }
    }
}

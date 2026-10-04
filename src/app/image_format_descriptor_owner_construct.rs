//! Mutex-backed image-format descriptor owner construction.
//!
//! `image_format_descriptor_owner_construct` — `FUN_081fd05c` at
//! `0x081fd05c`: 100 bytes through `0x081fd0c0` (96 instruction bytes,
//! then the vtable literal at `0x081fd0bc`). The next real function starts
//! at `0x081fd0c0`. Whole-image A32 decoding finds two inbound plain BLs
//! (`0x08208618`, `0x0822c1c0`), zero predicated BLs; the body contains
//! three plain BLs and zero predicated BLs.
//!
//! Installs vtable 0x08990e7c, creates the embedded mutex, clears three
//! state words, initializes 18 descriptor records, constructs an empty
//! refcounted handle, sets the selection sentinel to -1, clears the cursor
//! and flag, then links the owner to its own mutex. Returns the owner:
//! raw r0 is recovered from the handle slot, contrary to Ghidra's void type.
//! No behavioral deviations. Host pointer fields widen naturally under
//! repr(C); target offsets remain +4 mutex, +0xc link, +0x1c descriptors,
//! +0x2b0 handle, +0x2b4 selection, +0x2b8 cursor and +0x2bc flag.
//! Existing kernel dispatch must be installed on-device before construction.

use crate::app::image_format_descriptor_slots_initialize::image_format_descriptor_slots_initialize;
use crate::cxx::handle::{refcounted_ptr_construct_secondary, RefcountedBody};
use crate::kernel::sync_mutex::{mutex_create, Mutex};

#[repr(C)]
pub struct ImageFormatDescriptorOwner {
    pub vtable: u32,
    pub mutex: Mutex,
    pub mutex_link: *mut Mutex,
    pub state: [u32; 3],
    pub descriptors: [u32; 165],
    pub handle: *mut RefcountedBody,
    pub selection: u32,
    pub cursor: u32,
    pub flag: u8,
}

/// # Safety
/// `owner` must be aligned, writable storage for the complete object.
/// Construction overwrites existing ownership without releasing it, as in stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_descriptor_owner_construct(
    owner: *mut ImageFormatDescriptorOwner,
) -> *mut ImageFormatDescriptorOwner {
    (*owner).vtable = 0x0899_0e7c;
    let mutex = core::ptr::addr_of_mut!((*owner).mutex);
    mutex_create(mutex);
    (*owner).state = [0; 3];
    image_format_descriptor_slots_initialize(core::ptr::addr_of_mut!((*owner).descriptors).cast());
    refcounted_ptr_construct_secondary(core::ptr::addr_of_mut!((*owner).handle), 0, 0);
    (*owner).selection = u32::MAX;
    (*owner).cursor = 0;
    (*owner).flag = 0;
    (*owner).mutex_link = mutex;
    owner
}

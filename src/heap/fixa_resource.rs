//! FixA resource release.
//!
//! `release_element_resource` — retailOS `FUN_08048eb8` @ `0x08048eb8`
//! (144 bytes, `0x08048eb8..0x08048f48`; `0x08048f48` begins the next
//! independently linked function). A complete A32 decode finds two inbound
//! plain `bl` calls and one predicated `blne` call. Its sole outbound call is
//! `validate_fixa_magic`.
//!
//! After validating the FixA owner, the routine finds the first linked FixL
//! range containing `resource` (both endpoints are inclusive). It increments
//! that range's returned-resource count. A range that has not become full, or
//! is the sole range, receives `resource` at the head of its available list.
//! A full range that is not the sole list node tail-calls the existing FixL
//! unlink-and-destroy boundary. Deliberate deviation: Rust directly calls the
//! ported validator and the shared address-based destructor boundary rather
//! than preserving the retail tail branch.

use core::ptr::{addr_of, addr_of_mut};

use crate::heap::fixa::{destroy_fixl, FixaOwner};
use crate::heap::fixa_validate::validate_fixa_magic;

/// Target-width FixL words observed by `FUN_08048eb8`.
#[repr(C)]
struct FixaResourceRange {
    _magic: u32,
    _owner: u32,
    next: u32,
    capacity: u32,
    returned_count: u32,
    first_resource: u32,
    last_resource: u32,
    available_head: u32,
}

const _: () = assert!(core::mem::size_of::<FixaResourceRange>() == 0x20);

/// Returns a resource to the FixL range of a validated FixA owner.
///
/// # Safety
///
/// `owner` must be NULL or a valid target-layout FixA owner. Its linked ranges
/// and any selected `resource` must be valid writable target-layout objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.release_element_resource")]
#[inline(never)]
pub unsafe extern "C" fn release_element_resource(owner: *mut FixaOwner, resource: *mut u32) {
    if unsafe { validate_fixa_magic(owner.cast()) } == 0 {
        return;
    }

    let resource_address = resource as usize;
    let mut range_address = unsafe { addr_of!((*owner).first_fixl).read_volatile() };
    while range_address != 0 {
        let range = range_address as usize as *mut FixaResourceRange;
        let first = unsafe { addr_of!((*range).first_resource).read_volatile() } as usize;
        let last = unsafe { addr_of!((*range).last_resource).read_volatile() } as usize;
        if first <= resource_address && resource_address <= last {
            let returned = unsafe { addr_of!((*range).returned_count).read_volatile() } + 1;
            unsafe { addr_of_mut!((*range).returned_count).write_volatile(returned) };

            let capacity = unsafe { addr_of!((*range).capacity).read_volatile() };
            let next = unsafe { addr_of!((*range).next).read_volatile() };
            let head = unsafe { addr_of!((*owner).first_fixl).read_volatile() };
            if returned == capacity && (head != range_address || next != 0) {
                unsafe { destroy_fixl(range.cast()) };
                return;
            }

            let available = unsafe { addr_of!((*range).available_head).read_volatile() };
            unsafe {
                resource.write_volatile(available);
                addr_of_mut!((*range).available_head).write_volatile(resource as usize as u32);
            }
            return;
        }
        range_address = unsafe { addr_of!((*range).next).read_volatile() };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::LazyLock;

    const FIXA_MAGIC: u32 = 0x4669_7841;
    const SLAB_LEN: usize = 0x400;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::FIXA_RESOURCE_RELEASE, SLAB_LEN).map(|pointer| pointer as usize)
    });

    unsafe fn fixture() -> Option<(*mut FixaOwner, *mut FixaResourceRange, *mut u32, *mut u32)> {
        let base = *SLAB.as_ref()? as *mut u8;
        unsafe {
            base.write_bytes(0, SLAB_LEN);
            let owner = base.cast::<FixaOwner>();
            addr_of_mut!((*owner).magic).write(FIXA_MAGIC);
            let range = base.add(0x40).cast::<FixaResourceRange>();
            addr_of_mut!((*owner).first_fixl).write(range as usize as u32);
            addr_of_mut!((*range).capacity).write(2);
            addr_of_mut!((*range).first_resource).write(base.add(0x100) as usize as u32);
            addr_of_mut!((*range).last_resource).write(base.add(0x10c) as usize as u32);
            Some((owner, range, base.add(0x100).cast(), base.add(0x104).cast()))
        }
    }

    #[test]
    fn returns_resources_lifo_at_inclusive_range_edges() {
        let Some((owner, range, first, second)) = (unsafe { fixture() }) else { return };
        unsafe {
            release_element_resource(owner, first);
            assert_eq!(first.read(), 0);
            assert_eq!(addr_of!((*range).available_head).read(), first as usize as u32);
            release_element_resource(owner, second);
            assert_eq!(second.read(), first as usize as u32);
            assert_eq!(addr_of!((*range).available_head).read(), second as usize as u32);
            assert_eq!(addr_of!((*range).returned_count).read(), 2);
        }
    }

    #[test]
    fn ignores_invalid_owner_and_unowned_resource() {
        let Some((owner, range, _first, second)) = (unsafe { fixture() }) else { return };
        unsafe {
            addr_of_mut!((*owner).magic).write(0);
            second.write(0xdead_beef);
            release_element_resource(owner, second);
            assert_eq!(second.read(), 0xdead_beef);
            assert_eq!(addr_of!((*range).returned_count).read(), 0);

            addr_of_mut!((*owner).magic).write(FIXA_MAGIC);
            let outside = second.add(8);
            outside.write(0x1234_5678);
            release_element_resource(owner, outside);
            assert_eq!(outside.read(), 0x1234_5678);
            assert_eq!(addr_of!((*range).returned_count).read(), 0);
        }
    }
}

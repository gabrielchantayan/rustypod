//! Releases indexed container elements through their vtable slot.
//!
//! `container_release_indexed_elements` — retailOS `FUN_083d15dc` @
//! `0x083d15dc` (76 bytes, `0x083d15dc..0x083d1627`; the next independently
//! entered function starts at `0x083d1628`). Raw ARM decoding verifies two
//! inbound plain `bl` calls (`0x083d1674`, `0x083d16ac`) and no predicated
//! inbound `bl` calls. The body makes one plain direct `bl` to the established
//! `container_element_at_alias_6b14` @ `0x083d6b14`, plus one predicated
//! indirect `blxne` through each non-NULL element's vtable slot `+0x04`.
//!
//! When the byte at `container + 0x10` is nonzero, it walks signed indices
//! `[0, count)`, obtains each element, and invokes its unresolved slot `+0x04`
//! when present. Deliberate deviation: the ARM indirect dispatch uses target
//! u32 vtable words; host fixtures use typed native-pointer vtables.

use super::templates::container_element_at_alias_6b14;

/// Target-layout prefix read by the release walk.
#[repr(C)]
pub struct IndexedElementContainer {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

type ElementRelease = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
type ElementAt = unsafe extern "C" fn(*mut IndexedElementContainer, i32) -> *mut u8;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostIndexedElementContainer {
    pub element_at: ElementAt,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_element: *mut u8) {
    panic!("install indexed container release host operation before calling")
}

#[cfg(not(target_os = "none"))]
pub static mut INDEXED_ELEMENT_CONTAINER_RELEASE: ElementRelease = missing_release;

#[inline(always)]
unsafe fn release_element(element: *mut u8) {
    if element.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    {
        let vtable = element.cast::<u32>().read_volatile() as usize as *const u32;
        let release: ElementRelease = core::mem::transmute(vtable.add(0x04 / 4).read_volatile() as usize);
        release(element);
    }
    #[cfg(not(target_os = "none"))]
    unsafe { INDEXED_ELEMENT_CONTAINER_RELEASE(element) };
}

/// Releases every populated indexed element when the container is enabled.
///
/// # Safety
///
/// `container` must satisfy the unchecked retailOS layout and vtable contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_release_indexed_elements(container: *mut IndexedElementContainer) {
    #[cfg(target_os = "none")]
    {
        let base = container.cast::<u8>();
        if base.add(0x10).read_volatile() == 0 {
            return;
        }
        let count = base.add(0x04).cast::<i32>().read_volatile();
        let mut index = 0;
        while index < count {
            release_element(container_element_at_alias_6b14(base, index as usize));
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = container.cast::<HostIndexedElementContainer>();
        if (*host).enabled == 0 {
            return;
        }
        let mut index = 0;
        while index < (*host).count {
            release_element(((*host).element_at)(container, index));
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDICES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut RELEASED: [usize; 4] = [0; 4];
    static mut RELEASE_COUNT: usize = 0;
    static mut ELEMENTS: [*mut u8; 4] = [core::ptr::null_mut(); 4];

    unsafe extern "C" fn element_at(_: *mut IndexedElementContainer, index: i32) -> *mut u8 {
        unsafe {
            INDICES[INDEX_COUNT] = index;
            INDEX_COUNT += 1;
            ELEMENTS[index as usize]
        }
    }

    unsafe extern "C" fn record_release(element: *mut u8) {
        unsafe {
            RELEASED[RELEASE_COUNT] = element as usize;
            RELEASE_COUNT += 1;
        }
    }

    fn fixture(enabled: u8, count: i32) -> HostIndexedElementContainer {
        HostIndexedElementContainer { element_at, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_and_nonpositive_containers() {
        let _lock = LOCK.lock();
        unsafe {
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            INDEXED_ELEMENT_CONTAINER_RELEASE = record_release;
            container_release_indexed_elements((&mut fixture(0, 2) as *mut HostIndexedElementContainer).cast());
            container_release_indexed_elements((&mut fixture(1, 0) as *mut HostIndexedElementContainer).cast());
            container_release_indexed_elements((&mut fixture(1, -1) as *mut HostIndexedElementContainer).cast());
            assert_eq!(INDEX_COUNT, 0);
            assert_eq!(RELEASE_COUNT, 0);
        }
    }

    #[test]
    fn releases_nonnull_elements_in_signed_index_order() {
        let _lock = LOCK.lock();
        unsafe {
            let mut first = 0u8;
            let mut third = 0u8;
            ELEMENTS = [core::ptr::addr_of_mut!(first), core::ptr::null_mut(), core::ptr::addr_of_mut!(third), core::ptr::null_mut()];
            INDEX_COUNT = 0;
            RELEASE_COUNT = 0;
            INDEXED_ELEMENT_CONTAINER_RELEASE = record_release;
            container_release_indexed_elements((&mut fixture(1, 3) as *mut HostIndexedElementContainer).cast());
            assert_eq!(&INDICES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&RELEASED[..RELEASE_COUNT], &[core::ptr::addr_of_mut!(first) as usize, core::ptr::addr_of_mut!(third) as usize]);
        }
    }
}

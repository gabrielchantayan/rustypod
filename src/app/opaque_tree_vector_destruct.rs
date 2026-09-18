//! Opaque tree/vector owner destructor.
//!
//! `opaque_tree_vector_destruct` — original: `FUN_0811f548` @ `0x0811f548`
//! (72 bytes). Raw ARM establishes the complete 18-word body through
//! `0x0811f58c`; the next separately linked function starts at `0x0811f594`.
//! It has three direct plain `bl` instructions and no predicated internal
//! calls. Full-image A32 decoding finds four inbound calls: three plain `bl`
//! and one predicated `blne`.
//!
//! The destructor installs its vtable, clears the opaque tree at `this+0x18`,
//! releases each four-byte refcounted-body slot in `[this+0x04,this+0x0c)`,
//! then deallocates that slot array and returns `this`. Deliberate deviation:
//! the tree clear helper @ `0x083dc640` has no recovered semantic identity, so
//! it remains a fixed-address target call; host tests inject it as a seam.

const VTABLE_ADDRESS: u32 = 0x0898_2f30;
const SLOTS: usize = 0x04;
const SLOTS_END: usize = 0x08;
const SLOTS_CAPACITY: usize = 0x0c;
const TREE: usize = 0x18;

type TreeClear = unsafe extern "C" fn(*mut u8) -> *mut u8;
type Release = unsafe extern "C" fn(*mut *mut crate::cxx::handle::RefcountedBody);
type Dealloc = unsafe extern "C" fn(*mut u8, usize, usize);

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe extern "C" fn clear_tree(tree: *mut u8) -> *mut u8 {
    let clear: TreeClear = unsafe { core::mem::transmute(0x083d_c640usize) };
    unsafe { clear(tree) }
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn clear_tree(tree: *mut u8) -> *mut u8 { tree }

/// Destroys an opaque tree owner and returns its original address.
///
/// # Safety
/// `this` must point to the target's 32-bit layout. Its tree and every
/// non-NULL refcounted body must be valid for their corresponding teardown.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_tree_vector_destruct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_tree_vector_destruct(this: *mut u8) -> *mut u8 {
    unsafe {
        opaque_tree_vector_destruct_with(
            this,
            clear_tree,
            crate::cxx::handle::refcounted_body_release_dtor_variant,
            crate::heap::veneers::cxx_array_dealloc,
        )
    }
}

unsafe fn opaque_tree_vector_destruct_with(
    this: *mut u8,
    clear: TreeClear,
    release: Release,
    dealloc: Dealloc,
) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write(VTABLE_ADDRESS);
        clear(this.add(TREE));

        let begin = this.add(SLOTS).cast::<u32>().read();
        let end = this.add(SLOTS_END).cast::<u32>().read();
        let capacity = this.add(SLOTS_CAPACITY).cast::<u32>().read();
        let mut slot = begin as usize as *mut *mut crate::cxx::handle::RefcountedBody;
        let end = end as usize as *mut *mut crate::cxx::handle::RefcountedBody;
        while slot != end {
            release(slot);
            slot = slot.add(1);
        }
        let count = ((capacity.wrapping_sub(begin) as i32) >> 2) as usize;
        dealloc(begin as usize as *mut u8, count, 0);
    }
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TREE_CALLED: AtomicUsize = AtomicUsize::new(0);
    static RELEASED: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
    static DEALLOC_PTR: AtomicUsize = AtomicUsize::new(0);
    static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn recording_clear(tree: *mut u8) -> *mut u8 {
        TREE_CALLED.store(tree as usize, Ordering::Relaxed);
        tree
    }
    unsafe extern "C" fn recording_release(slot: *mut *mut crate::cxx::handle::RefcountedBody) {
        let index = RELEASED[0].fetch_add(1, Ordering::Relaxed);
        RELEASED[index + 1].store(slot as usize, Ordering::Relaxed);
    }
    unsafe extern "C" fn recording_dealloc(ptr: *mut u8, count: usize, elem: usize) {
        assert_eq!(elem, 0);
        DEALLOC_PTR.store(ptr as usize, Ordering::Relaxed);
        DEALLOC_COUNT.store(count, Ordering::Relaxed);
    }

    #[test]
    fn installs_vtable_clears_tree_releases_slots_and_deallocates_capacity() {
        let mut object = [0u32; 10];
        TREE_CALLED.store(0, Ordering::Relaxed);
        for value in &RELEASED { value.store(0, Ordering::Relaxed); }
        DEALLOC_PTR.store(usize::MAX, Ordering::Relaxed);
        DEALLOC_COUNT.store(usize::MAX, Ordering::Relaxed);

        let this = object.as_mut_ptr().cast::<u8>();
        assert_eq!(unsafe { opaque_tree_vector_destruct_with(this, recording_clear, recording_release, recording_dealloc) }, this);
        assert_eq!(object[0], VTABLE_ADDRESS);
        assert_eq!(TREE_CALLED.load(Ordering::Relaxed), unsafe { this.add(TREE) } as usize);
        assert_eq!(RELEASED[0].load(Ordering::Relaxed), 0);
        assert_eq!(DEALLOC_PTR.load(Ordering::Relaxed), 0);
        assert_eq!(DEALLOC_COUNT.load(Ordering::Relaxed), 0);
    }
}

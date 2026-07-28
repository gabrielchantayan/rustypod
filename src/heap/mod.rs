//! retailOS application heap (cluster 0x0819cd5c..0x0819d9d8 + veneers).
pub mod alloc_core;
pub mod block_deque;
pub mod block_mgr;
pub mod block_region;
pub mod dcache;
pub mod free_path;
pub mod init;
pub mod pool;
pub mod stats;
pub mod types;
pub mod veneers;
pub mod wrappers;

/// Cross-module wiring proof: every dispatch table defaults to the real
/// ports (the module headers' "once ported, point here" contract), so the
/// original call graph — region registration linking a real free block
/// into the descriptor's sentinel list, the free path taking the
/// (pre-kernel no-op) heap lock, the lazy default-heap init reaching
/// `heap_create` — runs end-to-end with no mocks installed.
///
/// Not covered on host, by necessity: paths through `heap_alloc_core`'s
/// free-list walk (host test builds represent links as u32 arena offsets,
/// incompatible with the pointer-linked list the other modules build —
/// see alloc_core.rs) and the auto-init region fallback (the descriptor
/// stores region addresses as u32, which truncates 64-bit host pointers —
/// see init.rs's SIGSEGV-probing test).
#[cfg(test)]
mod wiring_tests {
    extern crate std;
    use crate::heap::types::{FreeSentinel, HeapDescriptor, BLOCK_FREE, PREV_FREE};
    use crate::heap::{free_path, init, veneers, wrappers};
    use std::boxed::Box;

    /// Restores every wired default the heap paths dispatch through (other
    /// test modules leave their mocks installed; tests run serially).
    unsafe fn restore_wired_defaults() {
        core::ptr::addr_of_mut!(init::HEAP_INIT_OPS).write(init::DEFAULT_HEAP_INIT_OPS);
        core::ptr::addr_of_mut!(free_path::HEAP_MUTEX_HOOKS)
            .write(free_path::DEFAULT_HEAP_MUTEX_HOOKS);
        core::ptr::addr_of_mut!(free_path::HEAP_PANIC_HOOK)
            .write(free_path::DEFAULT_HEAP_PANIC_HOOK);
        core::ptr::addr_of_mut!(wrappers::HEAP_CORE_HOOKS)
            .write(wrappers::DEFAULT_HEAP_CORE_HOOKS);
        core::ptr::addr_of_mut!(veneers::HEAP_OPS).write(veneers::DEFAULT_HEAP_OPS);
        // Pre-kernel state: the wired heap_lock/heap_unlock must take the
        // original's no-op path (host pointers cannot round-trip through
        // the descriptor's 32-bit mutex slot anyway).
        core::ptr::addr_of_mut!(crate::kernel::sync_mutex::KERNEL_STARTED).write(0);
    }

    fn zeroed_desc() -> *mut HeapDescriptor {
        Box::into_raw(Box::new(unsafe { core::mem::zeroed::<HeapDescriptor>() }))
    }

    /// 8-aligned heap backing memory.
    #[repr(align(8))]
    struct Region([u8; 0x1000]);

    /// The free-list node overlay seen through the public `FreeSentinel`
    /// layout (same first three fields as free_path's node on host and
    /// target).
    unsafe fn node(header: *const u32) -> &'static FreeSentinel {
        &*(header as *const FreeSentinel)
    }

    #[test]
    fn add_region_links_a_real_free_block_through_the_wired_defaults() {
        unsafe {
            restore_wired_defaults();
            let desc = zeroed_desc();
            init::heap_desc_init(desc, 0, 0);
            let mut region = Box::new(Region([0; 0x1000]));
            let start = region.0.as_mut_ptr() as usize; // 8-aligned
            let size = 0x800usize;

            init::heap_add_region(desc, start, size);

            // Same carve as the spied init.rs tests...
            let header = (start + 8) as *mut u32;
            let block_size = (size - 16) as u32;
            assert_eq!((*desc).region_count, 1);
            assert_eq!((*desc).total_bytes, block_size);
            // ...but now the block really went through heap_free_insert:
            // marked free, accounted, footer written, terminator told its
            // predecessor is free, and linked under the sentinel.
            assert_eq!((*desc).free_bytes, block_size, "insert credits free_bytes");
            assert_eq!(header.read(), block_size | BLOCK_FREE);
            let footer = header.add((block_size as usize - 4) / 4).read();
            assert_eq!(footer, block_size, "footer copy at block end - 4");
            let terminator = header.add(block_size as usize / 4).read();
            assert_eq!(terminator, PREV_FREE, "terminator sees the free block");
            let sentinel = core::ptr::addr_of_mut!((*desc).sentinel);
            assert_eq!((*sentinel).next, header as *mut FreeSentinel, "list head");
            assert_eq!(node(header).prev, sentinel, "head points back at the sentinel");
            assert!(node(header).next.is_null(), "single-element list");
            // Pre-kernel: the wired lock pair was a no-op, no mutex made.
            assert_eq!((*desc).mutex_state, 0);
            assert_eq!((*desc).mutex_state2, 0);
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn heap_free_reaches_the_free_list_through_the_wired_defaults() {
        unsafe {
            restore_wired_defaults();
            let desc = zeroed_desc();
            init::heap_desc_init(desc, 0, 0);
            let mut arena = Box::new(Region([0; 0x1000]));
            let base = arena.0.as_mut_ptr();
            // A (allocated) | B (allocated, freed below) | C (allocated).
            for (off, flags) in [(0usize, 0x40u32), (0x40, 0x40), (0x80, 0x40)] {
                (base.add(off) as *mut u32).write(flags); // size_flags
                (base.add(off + 4) as *mut u32).write(0); // link_or_tag
            }
            let b = base.add(0x40) as *mut u32;

            free_path::heap_free(desc, (b as *mut u8).add(8), 2);

            assert_eq!(b.read(), 0x40 | BLOCK_FREE);
            assert_eq!((base.add(0x80) as *const u32).read(), 0x40 | PREV_FREE);
            assert_eq!((base.add(0x80 - 4) as *const u32).read(), 0x40, "footer");
            assert_eq!((*desc).free_bytes, 0x40);
            let sentinel = core::ptr::addr_of_mut!((*desc).sentinel);
            assert_eq!((*sentinel).next, b as *mut FreeSentinel);
            assert_eq!(node(b).prev, sentinel);
            assert!(node(b).next.is_null());
            // The wired mutex pair ran its pre-kernel no-op path.
            assert_eq!((*desc).mutex_state, 0);
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn lazy_default_heap_init_reaches_heap_create_through_the_wired_defaults() {
        unsafe {
            restore_wired_defaults();
            core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP)
                .write(core::ptr::null_mut());

            veneers::lazy_init_default_heap();

            // The handle is the storage descriptor, really initialized by
            // heap_desc_init (not a mock): 32 KB initial region recorded,
            // auto-init armed, nothing registered yet.
            let handle = core::ptr::addr_of!(crate::heap::types::DEFAULT_HEAP).read();
            assert!(!handle.is_null());
            let desc = handle as *mut HeapDescriptor;
            assert_eq!((*desc).initial_region_size, 0x8000);
            assert_eq!((*desc).region_count, 0);
            assert!((*desc).sentinel.next.is_null());
            // auto_init byte (low byte of the u32 field, as on target).
            assert_eq!(core::ptr::addr_of!((*desc).auto_init).cast::<u8>().read(), 1);
        }
    }
}

//! `construct_deque_context_and_mutex` — retailOS `FUN_08261b70` @ 0x08261b70.
//! True extent: 184 bytes, ending at pop {r4,r5,r6,r7,r8,pc} @ 0x08261c24;
//! the independent destructor starts at 0x08261c28. Whole-image aligned A32
//! decoding finds two inbound plain BLs (0x08261c58, 0x08261c60), no predicated
//! BLs or tail Bs; the body has nine plain BLs and no predicated BLs.
//!
//! Construct the 0x1c-byte mutex, then the 0x1c-byte opaque context, then an
//! empty four-byte-element deque at +0x38, clearing its map capacity at +0x60.
//! Return the owner derived from the context constructor's returned pointer.
//! Neither child initialization status stops construction.
//!
//! Deliberate deviations: the temporary deque constructed by 0x083df154 is
//! all-NULL with count zero (raw stores at 0x083df178..0x083df18c). Thus its
//! copied begin/end iterators compare equal on the first check at 0x083ea37c,
//! and the cleanup loop's count predicate @ 0x083d7600 is immediately true.
//! Elide that temporary, both iterator copies and the empty range/cleanup
//! calls. Reuse the existing equivalent `deque_construct` prefix initializer;
//! its NULL return is ignored, as are both original deque constructor returns.
//! Host pointer-bearing deque fields widen through the existing repr(C) layout;
//! mutex and opaque context retain their seven-u32-word storage each.

use core::ptr;
use crate::heap::block_deque::{deque_construct, BlockDeque};
use super::mutex::cxx_mutex_construct;
use super::opaque_context_initialize::initialize_opaque_context;

#[repr(C)]
pub struct DequeContextMutex {
    pub mutex_wrapper: [u32; 7],
    pub opaque_context: [u32; 7],
    pub deque: BlockDeque,
}

/// # Safety
/// `this` must be aligned writable storage for the complete object and meet
/// the mutex and opaque-context constructors' dependency contracts. No NULL
/// check is performed. Scope seeds preserve the incoming r2/r3 register values.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn construct_deque_context_and_mutex(
    this: *mut DequeContextMutex,
    mutex_param_2: usize,
    scope_word0: usize,
    scope_word1: usize,
) -> *mut DequeContextMutex {
    let mutex = cxx_mutex_construct(this.cast(), mutex_param_2, scope_word0, scope_word1);
    let context = initialize_opaque_context(mutex.cast::<u32>().add(7));
    finish_construct(context)
}

#[inline(always)]
unsafe fn finish_construct(context: *mut u32) -> *mut DequeContextMutex {
    let owner = context.sub(7).cast::<DequeContextMutex>();
    let deque = ptr::addr_of_mut!((*owner).deque);
    ptr::addr_of_mut!((*deque).map_cap).write(0);
    deque_construct(deque.cast());
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::block_deque::DequeIter;

    #[test]
    fn empty_deque_replaces_poison_even_when_children_report_errors() {
        for status in [0, 0x1a, 0x27, u32::MAX] {
            let poison = DequeIter {
                cur: 4usize as *mut u8,
                seg_base: 8usize as *mut u8,
                seg_end: 12usize as *mut u8,
                seg_slot: 16usize as *mut *mut u8,
            };
            #[repr(C)]
            struct Guarded { before: [u32; 2], object: DequeContextMutex, after: [u32; 2] }
            let mut guarded = Guarded {
                before: [0x1234; 2],
                object: DequeContextMutex {
                    mutex_wrapper: [status; 7],
                    opaque_context: [status; 7],
                    deque: BlockDeque { begin: poison, end: poison, count: u32::MAX,
                        map: 20usize as *mut *mut u8, map_cap: u32::MAX },
                },
                after: [0x5678; 2],
            };
            let object = ptr::addr_of_mut!(guarded.object);
            unsafe {
                assert_eq!(finish_construct(ptr::addr_of_mut!((*object).opaque_context).cast()), object);
            }
            assert_eq!(guarded.object.mutex_wrapper, [status; 7]);
            assert_eq!(guarded.object.opaque_context, [status; 7]);
            let deque = &guarded.object.deque;
            for iterator in [&deque.begin, &deque.end] {
                assert!(iterator.cur.is_null());
                assert!(iterator.seg_base.is_null());
                assert!(iterator.seg_end.is_null());
                assert!(iterator.seg_slot.is_null());
            }
            assert_eq!(deque.count, 0);
            assert!(deque.map.is_null());
            assert_eq!(deque.map_cap, 0);
            assert_eq!(guarded.before, [0x1234; 2]);
            assert_eq!(guarded.after, [0x5678; 2]);
        }
    }

    #[test]
    fn target_word_storage_keeps_children_and_deque_disjoint() {
        assert_eq!(core::mem::offset_of!(DequeContextMutex, opaque_context), 0x1c);
        assert_eq!(core::mem::offset_of!(DequeContextMutex, deque), 0x38);
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(core::mem::size_of::<DequeContextMutex>(), 0x64);
            assert_eq!(core::mem::offset_of!(BlockDeque, map_cap), 0x28);
        }
    }
}

//! Push an entry onto an owner object's growable word stack.
//!
//! `object_stack_push` is `FUN_0803c12c` @ `0x0803c12c`. Raw `osos.dec`
//! words establish the exact 140-byte extent `0x0803c12c..0x0803c1b8`: the
//! final `pop {r4,r5,r6,pc}` sits at `0x0803c1b4` and `0x0803c1b8` begins a
//! distinct thunk (`mov r1,r0; ldr r0,[pc,#4]; ldr r0,[r0]; b 0x08058c3c`),
//! matching Ghidra's 140-byte size. Decoding every ARM B/BL word in
//! `osos.dec` finds exactly five inbound calls, all plain `bl`
//! (`0x08061748`, `0x0806359c`, `0x0806368c`, `0x08065cd4`, `0x0812cc20`),
//! none predicated — matching Ghidra's call-site count.
//!
//! The owner keeps a current entry at `+0xf40`, a tag-4 word array at
//! `+0xf64`, and its element count at `+0xf68`. The body allocates
//! `(count + 1) * 4` bytes with `malloc_tag4` @ `0x0805d1d4` and returns 0
//! on failure. When `entry == current` it copies all `count` words and
//! appends `entry`; otherwise it copies `count - 1` words, stores `entry` at
//! index `count - 1`, and re-appends the displaced `current` at index
//! `count`. It then installs the new array, increments the count, frees the
//! old array with `free_tag4` @ `0x0805d070`, posts the change notification
//! `FUN_0813e194`, and returns 1. The copy loop uses signed `blt`, so a
//! `count` of 0 on the mismatched path copies nothing and stores `entry` at
//! index -1 exactly like the original (unreachable in practice: a live
//! owner always has `count >= 1`).
//!
//! Deliberate deviations: the still-unported notification poster
//! `FUN_0813e194` (prologue decoded: allocates a `0x48`-byte object,
//! initializes it via `FUN_0813e474`, then dispatches through a global
//! listener) is reached at its fixed load address on target and replaced by
//! a test hook on host; the original calls it with `free_tag4`'s dead
//! return value in `r0`, which its first instruction overwrites, so this
//! port passes no argument. The per-word copy uses volatile accesses so
//! LLVM cannot fold the loop into a `memcpy` call.

use crate::heap::veneers::{free_tag4, malloc_tag4};

const CURRENT_OFFSET: usize = 0xf40;
const ITEMS_OFFSET: usize = 0xf64;
const COUNT_OFFSET: usize = 0xf68;

const CHANGE_NOTIFICATION_ADDRESS: usize = 0x0813_e194;

type AllocateFn = unsafe extern "C" fn(usize) -> *mut u8;
type FreeFn = unsafe extern "C" fn(*mut u8);
type NotifyFn = unsafe extern "C" fn();

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_change_notification() {
    panic!("install a change-notification poster before testing object_stack_push")
}

/// Host replacement for the unported `FUN_0813e194`; device builds call its
/// fixed retailOS load address directly.
#[cfg(not(target_os = "none"))]
static mut CHANGE_NOTIFICATION: NotifyFn = missing_change_notification;

#[inline(always)]
unsafe fn change_notification() -> NotifyFn {
    #[cfg(target_os = "none")]
    {
        core::mem::transmute(CHANGE_NOTIFICATION_ADDRESS)
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(CHANGE_NOTIFICATION))
    }
}

#[inline(always)]
unsafe fn object_stack_push_with(
    owner: *mut u8,
    entry: u32,
    allocate: AllocateFn,
    free: FreeFn,
    notify: NotifyFn,
) -> u32 {
    // The +0xf64 items field is a target-width pointer: read and written as
    // a u32 word so host fixtures stay 32-bit (trap: host pointers are 8
    // bytes and the field is only 4-byte aligned).
    let items = owner.add(ITEMS_OFFSET).cast::<u32>().read() as usize as *mut u32;
    let count = owner.add(COUNT_OFFSET).cast::<u32>().read() as i32;
    let grown = allocate((count as u32 as usize + 1) * 4).cast::<u32>();
    if grown.is_null() {
        return 0;
    }

    let current = owner.add(CURRENT_OFFSET).cast::<u32>().read();
    // Equal: copy all `count` words. Mismatch: copy `count - 1` words and
    // re-append the displaced current entry after the new one. Signed
    // compare mirrors the original `blt` loop.
    let copied = if current == entry { count } else { count - 1 };
    let mut index = 0i32;
    while index < copied {
        let word = items.offset(index as isize).read_volatile();
        grown.offset(index as isize).write_volatile(word);
        index += 1;
    }
    grown.offset(copied as isize).write_volatile(entry);
    if current != entry {
        grown.offset(copied as isize + 1).write_volatile(current);
    }

    owner.add(ITEMS_OFFSET).cast::<u32>().write(grown as usize as u32);
    owner.add(COUNT_OFFSET).cast::<u32>().write(count as u32 + 1);
    free(items.cast());
    notify();
    1
}

/// object_stack_push — original: `FUN_0803c12c` @ `0x0803c12c` (140 bytes;
/// five plain `bl` callers, zero predicated; body makes three plain `bl`
/// calls: `malloc_tag4`, `free_tag4`, `FUN_0813e194`).
///
/// Pushes `entry` onto the owner's word stack, growing the tag-4 array by
/// one element; see the module header for the exact append/replace rule.
/// Returns 1 on success, 0 when the growth allocation fails (owner
/// untouched). `owner` must point to at least `0xf6c` readable/writable
/// bytes and, on the success path, its `+0xf64` array must hold `+0xf68`
/// readable words and be freeable by `free_tag4`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_stack_push(owner: *mut u8, entry: u32) -> u32 {
    object_stack_push_with(owner, entry, malloc_tag4, free_tag4, change_notification())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_CALLS: u32 = 0;
    static mut ALLOC_SIZE: usize = 0;
    static mut ALLOC_NULL: bool = false;
    static mut FREED: *mut u8 = core::ptr::null_mut();
    static mut NOTIFY_CALLS: u32 = 0;

    const SLAB_LEN: usize = 0x2000;
    const OLD_OFFSET: usize = 0;
    const NEW_OFFSET: usize = 0x1000;

    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        ALLOC_CALLS += 1;
        ALLOC_SIZE = size;
        if ALLOC_NULL {
            core::ptr::null_mut()
        } else {
            slab().add(NEW_OFFSET)
        }
    }

    unsafe extern "C" fn free(ptr: *mut u8) {
        FREED = ptr;
    }

    unsafe extern "C" fn notify() {
        NOTIFY_CALLS += 1;
    }

    unsafe fn reset() {
        ALLOC_CALLS = 0;
        ALLOC_SIZE = 0;
        ALLOC_NULL = false;
        FREED = core::ptr::null_mut();
        NOTIFY_CALLS = 0;
        core::ptr::write_bytes(slab(), 0, SLAB_LEN);
    }

    /// The single never-unmapped fixture slab, mapped lazily once; both the
    /// old items array and every growth allocation live inside the low 32 bits.
    unsafe fn slab() -> *mut u8 {
        static mut SLAB: *mut u8 = core::ptr::null_mut();
        if SLAB.is_null() {
            SLAB = crate::testing::try_map_u32_slab(crate::testing::hints::OBJECT_STACK_PUSH, SLAB_LEN)
                .unwrap_or(core::ptr::null_mut());
        }
        if SLAB.is_null() {
            crate::testing::note_missing_u32_fixture("ui/object_stack_push");
        }
        SLAB
    }

    unsafe fn grown() -> *mut u32 {
        slab().add(NEW_OFFSET).cast()
    }

    /// Owner layout: words 0..0x3fc; +0xf40 current, +0xf64 items (u32 word),
    /// +0xf68 count.
    #[repr(C, align(4))]
    struct Owner {
        words: [u32; 0x3fc],
    }

    impl Owner {
        fn as_ptr(&mut self) -> *mut u8 {
            core::ptr::addr_of_mut!(self.words).cast()
        }

        fn current(&mut self) -> &mut u32 {
            &mut self.words[CURRENT_OFFSET / 4]
        }

        fn items(&mut self) -> &mut u32 {
            &mut self.words[ITEMS_OFFSET / 4]
        }

        fn count(&mut self) -> &mut u32 {
            &mut self.words[COUNT_OFFSET / 4]
        }
    }

    unsafe fn old_items() -> *mut u32 {
        slab().add(OLD_OFFSET).cast()
    }

    #[test]
    fn allocation_failure_leaves_owner_untouched() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            if slab().is_null() {
                return;
            }
            reset();
            let mut owner = Owner { words: [0; 0x3fc] };
            *owner.current() = 9;
            *owner.items() = old_items() as u32;
            *owner.count() = 3;
            ALLOC_NULL = true;
            assert_eq!(object_stack_push_with(owner.as_ptr(), 42, allocate, free, notify), 0);
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_SIZE, 16);
            assert_eq!(NOTIFY_CALLS, 0);
            assert!(FREED.is_null());
            assert_eq!(*owner.items(), old_items() as u32);
            assert_eq!(*owner.count(), 3);
        }
    }

    #[test]
    fn equal_entry_appends_all_words_then_entry() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            if slab().is_null() {
                return;
            }
            reset();
            core::ptr::copy_nonoverlapping([10u32, 20, 30].as_ptr(), old_items(), 3);
            let mut owner = Owner { words: [0; 0x3fc] };
            *owner.current() = 30;
            *owner.items() = old_items() as u32;
            *owner.count() = 3;
            assert_eq!(object_stack_push_with(owner.as_ptr(), 30, allocate, free, notify), 1);
            assert_eq!(ALLOC_SIZE, 16);
            assert_eq!(std::slice::from_raw_parts(grown(), 4), &[10, 20, 30, 30]);
            assert_eq!(*owner.items(), grown() as u32);
            assert_eq!(*owner.count(), 4);
            assert_eq!(FREED, old_items().cast());
            assert_eq!(NOTIFY_CALLS, 1);
        }
    }

    #[test]
    fn mismatched_entry_replaces_last_and_reappends_current() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            if slab().is_null() {
                return;
            }
            reset();
            core::ptr::copy_nonoverlapping([10u32, 20, 30].as_ptr(), old_items(), 3);
            let mut owner = Owner { words: [0; 0x3fc] };
            *owner.current() = 30;
            *owner.items() = old_items() as u32;
            *owner.count() = 3;
            assert_eq!(object_stack_push_with(owner.as_ptr(), 99, allocate, free, notify), 1);
            assert_eq!(ALLOC_SIZE, 16);
            // count-1 words copied, entry replaces the dropped tail, current follows.
            assert_eq!(std::slice::from_raw_parts(grown(), 4), &[10, 20, 99, 30]);
            assert_eq!(*owner.count(), 4);
            assert_eq!(FREED, old_items().cast());
            assert_eq!(NOTIFY_CALLS, 1);
        }
    }

    #[test]
    fn single_element_mismatch_drops_it_for_entry() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            if slab().is_null() {
                return;
            }
            reset();
            core::ptr::copy_nonoverlapping([55u32].as_ptr(), old_items(), 1);
            let mut owner = Owner { words: [0; 0x3fc] };
            *owner.current() = 55;
            *owner.items() = old_items() as u32;
            *owner.count() = 1;
            assert_eq!(object_stack_push_with(owner.as_ptr(), 77, allocate, free, notify), 1);
            assert_eq!(ALLOC_SIZE, 8);
            assert_eq!(std::slice::from_raw_parts(grown(), 2), &[77, 55]);
            assert_eq!(*owner.count(), 2);
            assert_eq!(NOTIFY_CALLS, 1);
        }
    }

    #[test]
    fn empty_stack_with_equal_entry_appends() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            if slab().is_null() {
                return;
            }
            reset();
            let mut owner = Owner { words: [0; 0x3fc] };
            *owner.current() = 5;
            *owner.items() = 0;
            *owner.count() = 0;
            assert_eq!(object_stack_push_with(owner.as_ptr(), 5, allocate, free, notify), 1);
            assert_eq!(ALLOC_SIZE, 4);
            assert_eq!(grown().read(), 5);
            assert_eq!(*owner.count(), 1);
            assert!(FREED.is_null());
            assert_eq!(NOTIFY_CALLS, 1);
        }
    }
}

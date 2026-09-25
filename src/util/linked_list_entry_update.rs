//! `linked_list_entry_update` — original: `FUN_08059110` @ 0x08059110
//! (120 bytes; three direct `bl` call sites, all unconditional: 0x08051600,
//! 0x08059d28, and 0x08065dfc).
//!
//! Raw `osos.dec` establishes the exact extent `0x08059110..0x08059188`; the
//! independent function beginning with `stmdb sp!,{r4,r5,r6,r7,lr}` follows.
//! The routine looks up and promotes `key` in `list`. A miss uses the supplied
//! candidate payload, while a hit derives the entry from the returned payload.
//! It stores a four-byte value directly when `list + 0x04 == 4`; otherwise it
//! calls bcopy with that field as the byte count. It then clears entry +0x08 and
//! stores the key at entry +0x0c.
//!
//! # Deliberate deviations
//!
//! The direct `FUN_08053850` and `FUN_08042cbc` calls use their established
//! Rust ports rather than retail addresses. Raw target offsets are represented
//! with byte pointers so host pointers cannot change their meaning.

use core::ptr;

use crate::libc::bcopy::bcopy;
use crate::util::linked_list_find_and_promote::{linked_list_find_and_promote, LinkedListHeader};

type FindAndPromote = unsafe extern "C" fn(u32, *mut LinkedListHeader, *mut *mut u8) -> i32;
type Bcopy = unsafe extern "C" fn(*const u8, *mut u8, usize);

/// Volatile dispatch preserves retailOS's direct bcopy call boundary and stops
/// LLVM recognizing the call as an AEABI memmove builtin.
static BCOPY_PORT: Bcopy = bcopy;

#[inline(always)]
unsafe fn linked_list_entry_update_with(
    list: *mut u8,
    key: u32,
    value: *const u8,
    candidate_payload: *mut u8,
    find_and_promote: FindAndPromote,
    copy: Bcopy,
) {
    let mut payload = candidate_payload;
    let result = unsafe { find_and_promote(key, list.cast(), &mut payload) };
    let entry = if result == -123 {
        candidate_payload.sub(0x14)
    } else if result == 0 {
        payload.sub(0x14)
    } else {
        ptr::null_mut()
    };

    let element_size = unsafe { (list.add(4) as *const u32).read() };
    if element_size == 4 {
        unsafe { (entry.add(0x14) as *mut u32).write((value as *const u32).read()) };
    } else {
        unsafe { copy(value, entry.add(0x14), element_size as usize) };
    }
    unsafe { (entry.add(8) as *mut u32).write(0) };
    unsafe { (entry.add(0xc) as *mut u32).write(key) };
}

/// `linked_list_entry_update` — original: `FUN_08059110` @ 0x08059110 (120 bytes).
///
/// Updates an existing list entry for `key`, or initializes the entry whose
/// payload is `candidate_payload` if no matching entry exists. The list's
/// `+0x04` word is its element size.
///
/// # Safety
///
/// `list`, `value`, and the selected entry must satisfy the retail pointer and
/// size assumptions; an unexpected lookup status dereferences NULL as retailOS does.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.linked_list_entry_update")]
#[inline(never)]
pub unsafe extern "C" fn linked_list_entry_update(
    list: *mut u8,
    key: u32,
    value: *const u8,
    candidate_payload: *mut u8,
) {
    unsafe {
        linked_list_entry_update_with(
            list,
            key,
            value,
            candidate_payload,
            linked_list_find_and_promote,
            ptr::read_volatile(ptr::addr_of!(BCOPY_PORT)),
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static LOOKUP_PAYLOAD: AtomicUsize = AtomicUsize::new(0);
    static LOOKUP_KEY: AtomicUsize = AtomicUsize::new(0);
    static COPY_LENGTH: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn lookup_hit(key: u32, _list: *mut LinkedListHeader, output: *mut *mut u8) -> i32 {
        LOOKUP_KEY.store(key as usize, Ordering::Relaxed);
        unsafe { output.write(LOOKUP_PAYLOAD.load(Ordering::Relaxed) as *mut u8) };
        0
    }

    unsafe extern "C" fn lookup_miss(_key: u32, _list: *mut LinkedListHeader, _output: *mut *mut u8) -> i32 {
        -123
    }

    unsafe extern "C" fn recording_bcopy(src: *const u8, dst: *mut u8, len: usize) {
        COPY_LENGTH.store(len, Ordering::Relaxed);
        unsafe { ptr::copy(src, dst, len) };
    }

    #[test]
    fn hit_uses_returned_payload_and_word_copy() {
        let _lock = TEST_LOCK.lock();
        let mut list = [0u32; 5];
        list[1] = 4;
        let mut entry = [0u8; 40];
        let value = 0xdecafbad_u32;
        LOOKUP_PAYLOAD.store(unsafe { entry.as_mut_ptr().add(0x14) as usize }, Ordering::Relaxed);
        unsafe {
            linked_list_entry_update_with(
                list.as_mut_ptr().cast(), 0x1234, (&value as *const u32).cast(), core::ptr::null_mut(), lookup_hit, recording_bcopy,
            );
        }
        assert_eq!(LOOKUP_KEY.load(Ordering::Relaxed), 0x1234);
        assert_eq!(unsafe { (entry.as_ptr().add(0x14) as *const u32).read() }, value);
        assert_eq!(unsafe { (entry.as_ptr().add(8) as *const u32).read() }, 0);
        assert_eq!(unsafe { (entry.as_ptr().add(12) as *const u32).read() }, 0x1234);
        assert_eq!(COPY_LENGTH.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn miss_uses_candidate_payload_and_element_size_for_bcopy() {
        let _lock = TEST_LOCK.lock();
        let mut list = [0u32; 5];
        list[1] = 6;
        let mut entry = [0u8; 40];
        let value = [1u8, 2, 3, 4, 5, 6];
        COPY_LENGTH.store(0, Ordering::Relaxed);
        unsafe {
            linked_list_entry_update_with(
                list.as_mut_ptr().cast(), 0xfeed, value.as_ptr(), entry.as_mut_ptr().add(0x14), lookup_miss, recording_bcopy,
            );
        }
        assert_eq!(&entry[0x14..0x1a], &value);
        assert_eq!(COPY_LENGTH.load(Ordering::Relaxed), value.len());
        assert_eq!(unsafe { (entry.as_ptr().add(8) as *const u32).read() }, 0);
        assert_eq!(unsafe { (entry.as_ptr().add(12) as *const u32).read() }, 0xfeed);
    }
}

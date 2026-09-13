//! `resolve_tagged_cros_payload` — original: `FUN_081e01bc` @ 0x081e01bc
//! (196 bytes including its trailing literal pool, 0x081e01bc..0x081e0280;
//! Ghidra's 192-byte instruction extent omits the word at 0x081e027c).
//! Exactly **6 inbound direct `bl` sites** were decoded in `osos.dec`, all
//! unconditional: 0x081e0890, 0x081e08b0, 0x081e08d0, 0x081e096c,
//! 0x081e098c, and 0x081e09ac. Its body makes six unconditional `bl` calls:
//! two each to `FUN_08184f98`, and one each to `FUN_08184ed0`,
//! `FUN_08184f84`, `FUN_08184bd4`, and `FUN_083e7448`.
//!
//! It scans `entry_count` pointers in `entries` for `resource_tag` at entry
//! `+0x04`. For every match it creates a resource list with `FUN_08184ed0`,
//! scans that list for an entry tagged `CROS` (`0x534f5243`) at `+0x04`, and
//! copies the first two words of `FUN_08184bd4`'s 12-byte result to the two
//! output words. The temporary list is released after each outer match. Later
//! matches overwrite earlier outputs; no match leaves both output words alone.
//!
//! `FUN_08184ed0` is not ported. Device builds use a literal veneer to its
//! verified load address; host builds use fixture seams for that factory, the
//! target-word vector count, and `FUN_08184bd4`'s copy. Those seams are the
//! deliberate host-only deviation required because firmware vectors store
//! 32-bit pointers while host pointers are wider.

#[cfg(not(target_arch = "arm"))]
use core::ptr;

use crate::util::first_entry_payload::{copy_first_entry_payload, FirstEntryPayload};
use crate::util::object_release_slot1::object_release_slot1;
use crate::util::ptr_vector::{ptr_vector_at, ptr_vector_count};

const CROS_RESOURCE_TAG: u32 = 0x534f_5243;
const ENTRY_TAG_OFFSET: usize = 0x04;
const ENTRY_PAYLOAD_OWNER_OFFSET: usize = 0x08;

/// ABI of the unported resource-list clone/factory at `0x08184ed0`.
#[cfg(not(target_arch = "arm"))]
type RetailCloneResourceList = unsafe extern "C" fn(entry: *mut u8) -> *mut u8;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_clone_resource_list(entry: *mut u8) -> *mut u8;
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_clone_resource_list(_entry: *mut u8) -> *mut u8 {
    panic!("resolve_tagged_cros_payload requires a host resource-list fixture")
}

#[cfg(not(target_arch = "arm"))]
static mut RETAIL_CLONE_RESOURCE_LIST: RetailCloneResourceList = missing_retail_clone_resource_list;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_host_vector_count(_owner: *const u8) -> i32 {
    panic!("resolve_tagged_cros_payload requires a host vector-count fixture")
}

#[cfg(not(target_arch = "arm"))]
static mut HOST_VECTOR_COUNT: unsafe extern "C" fn(*const u8) -> i32 = missing_host_vector_count;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_copy_first_entry_payload(
    _owner_input: *mut u8,
    _output: *mut FirstEntryPayload,
) {
    panic!("resolve_tagged_cros_payload requires a host payload-copy fixture")
}

#[cfg(not(target_arch = "arm"))]
static mut HOST_COPY_FIRST_ENTRY_PAYLOAD: unsafe extern "C" fn(*mut u8, *mut FirstEntryPayload) =
    missing_copy_first_entry_payload;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn clone_resource_list(entry: *mut u8) -> *mut u8 {
    unsafe { retail_clone_resource_list(entry) }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn clone_resource_list(entry: *mut u8) -> *mut u8 {
    unsafe { ptr::read_volatile(ptr::addr_of!(RETAIL_CLONE_RESOURCE_LIST))(entry) }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn resource_list_count(owner: *const u8) -> i32 {
    unsafe { ptr_vector_count(owner) }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn resource_list_count(owner: *const u8) -> i32 {
    unsafe { ptr::read_volatile(ptr::addr_of!(HOST_VECTOR_COUNT))(owner) }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn copy_payload(owner_input: *mut u8, output: *mut FirstEntryPayload) {
    unsafe { copy_first_entry_payload(owner_input, output) }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn copy_payload(owner_input: *mut u8, output: *mut FirstEntryPayload) {
    unsafe { ptr::read_volatile(ptr::addr_of!(HOST_COPY_FIRST_ENTRY_PAYLOAD))(owner_input, output) }
}

// The port lives in the payload, so this literal veneer preserves the retail
// AAPCS call into the original body at its fixed load address.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_clone_resource_list
    .type retail_clone_resource_list, %function
retail_clone_resource_list:
    ldr     pc, [pc, #-4]
    .word   0x08184ed0
    .size retail_clone_resource_list, . - retail_clone_resource_list
"#
);

/// resolve_tagged_cros_payload — original: `FUN_081e01bc` @ 0x081e01bc
/// (196 bytes including its literal pool; six verified inbound unconditional
/// `bl` sites at 0x081e0890, 0x081e08b0, 0x081e08d0, 0x081e096c,
/// 0x081e098c, and 0x081e09ac).
///
/// Scans the explicit-length `entries` pointer vector. Matching outer entries
/// create a temporary list, whose `CROS`-tagged entries supply a pointer-to-
/// pointer at `+0x08` to [`copy_first_entry_payload`]. The payload's first and
/// second words overwrite `first_out` and `second_out`; neither is initialized
/// or written on unmatched paths. Both index values undergo the original
/// `lsl #16; asr #16` conversion before the vector accessor, and the inner
/// signed count is compared as unsigned, matching the ARM `bcc` loops.
///
/// # Safety
/// `entries` must identify an owner accepted by `ptr_vector_at` for each
/// index below `entry_count`. Every matching entry must have a readable tag at
/// `+0x04`; the factory result, its vector, and every matching inner entry's
/// pointer slot at `+0x08` must be valid. `first_out` and `second_out` must be
/// writable whenever an inner `CROS` entry matches. These unchecked contracts
/// mirror the retail loads and calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resolve_tagged_cros_payload")]
#[inline(never)]
pub unsafe extern "C" fn resolve_tagged_cros_payload(
    _context: *mut u8,
    entries: *const u8,
    entry_count: u32,
    resource_tag: u32,
    first_out: *mut u32,
    second_out: *mut u32,
) {
    for outer_index in 0..entry_count {
        let vector_index = (outer_index as i16 as i32) as u32;
        let entry = unsafe { ptr_vector_at(entries, vector_index) };
        let entry_tag = unsafe { (entry.add(ENTRY_TAG_OFFSET) as *const u32).read_volatile() };
        if entry_tag != resource_tag {
            continue;
        }

        let mut resource_list = unsafe { clone_resource_list(entry) };
        let resource_count = unsafe { resource_list_count(resource_list) } as u32;
        for inner_index in 0..resource_count {
            let vector_index = (inner_index as i16 as i32) as u32;
            let resource = unsafe { ptr_vector_at(resource_list, vector_index) };
            let resource_tag = unsafe { (resource.add(ENTRY_TAG_OFFSET) as *const u32).read_volatile() };
            if resource_tag != CROS_RESOURCE_TAG {
                continue;
            }

            let payload_owner = unsafe {
                (resource.add(ENTRY_PAYLOAD_OWNER_OFFSET) as *const *mut *mut u8)
                    .read_volatile()
                    .read()
            };
            let mut payload = FirstEntryPayload {
                first: 0,
                second: 0,
                kind: 0,
                tail: [0; 3],
            };
            unsafe { copy_payload(payload_owner, &mut payload) };
            unsafe {
                first_out.write(payload.first);
                second_out.write(payload.second);
            }
        }
        unsafe { object_release_slot1(&mut resource_list) };
    }
}

/// Reads the target-width indirect u32 stored in a resource entry at `+0x08`.
///
/// The first load is deliberately a u32 even on hosts: retailOS stores this
/// pointer in one ARM word, so host tests map its pointed-to value below 4 GiB.
#[inline(always)]
unsafe fn resource_indirect_value(resource: *const u8) -> u32 {
    let value_address = unsafe {
        (resource.add(ENTRY_PAYLOAD_OWNER_OFFSET) as *const u32).read_volatile()
    };
    unsafe { (value_address as usize as *const u32).read_volatile() }
}


/// resolve_tagged_cros_value — original: `FUN_081e011c` @ 0x081e011c
/// (156 bytes including its literal pool; six verified inbound unconditional
/// `bl` sites at 0x081e0a08, 0x081e0a24, 0x081e0a40, 0x081e0a70,
/// 0x081e0a8c, and 0x081e0aa8).
///
/// Scans the explicit-length `entries` pointer vector. Each outer entry tagged
/// `resource_tag` creates a temporary list; each `CROS` entry in that list
/// writes the u32 indirectly referenced by its `+0x08` field to `value_out`.
/// Later matches overwrite earlier values, while no match writes `value_out`.
/// Both loop indices undergo the original `lsl #16; asr #16` conversion; the
/// inner signed count is compared as unsigned, matching ARM `bcc`.
///
/// # Safety
/// `entries` must identify an owner accepted by `ptr_vector_at` for every
/// index below `entry_count`. Matching outer and inner entries must expose
/// readable tags at `+0x04`; a matching inner entry must expose a readable
/// pointer at `+0x08`, and that pointer must identify a readable u32.
/// `value_out` must be writable whenever an inner `CROS` entry matches.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resolve_tagged_cros_value")]
#[inline(never)]
pub unsafe extern "C" fn resolve_tagged_cros_value(
    _context: *mut u8,
    entries: *const u8,
    entry_count: u32,
    resource_tag: u32,
    value_out: *mut u32,
) {
    for outer_index in 0..entry_count {
        let vector_index = (outer_index as i16 as i32) as u32;
        let entry = unsafe { ptr_vector_at(entries, vector_index) };
        let entry_tag = unsafe { (entry.add(ENTRY_TAG_OFFSET) as *const u32).read_volatile() };
        if entry_tag != resource_tag {
            continue;
        }

        let mut resource_list = unsafe { clone_resource_list(entry) };
        let resource_count = unsafe { resource_list_count(resource_list) } as u32;
        for inner_index in 0..resource_count {
            let vector_index = (inner_index as i16 as i32) as u32;
            let resource = unsafe { ptr_vector_at(resource_list, vector_index) };
            let inner_tag = unsafe { (resource.add(ENTRY_TAG_OFFSET) as *const u32).read_volatile() };
            if inner_tag == CROS_RESOURCE_TAG {
                unsafe { value_out.write(resource_indirect_value(resource)) };
            }
        }
        unsafe { object_release_slot1(&mut resource_list) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CLONE_CALLS: usize = 0;
    static mut COPY_INPUTS: [usize; 4] = [0; 4];
    static mut COPY_CALLS: usize = 0;
    static mut RELEASE_CALLS: usize = 0;
    static INDIRECT_VALUE_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TAGGED_RESOURCE_VALUE, 0x1000).map(|pointer| pointer as usize)
    });

    const PTR: usize = core::mem::size_of::<*mut u8>();
    const VECTOR_OFFSET: usize = 0x14;

    #[repr(C)]
    struct OuterEntry {
        unused: u32,
        tag: u32,
        clone_result: *mut u8,
    }

    #[repr(C)]
    struct InnerEntry {
        unused: u32,
        tag: u32,
        payload_owner: *mut *mut u8,
    }

    #[repr(C)]
    struct IndirectValueEntry {
        unused: u32,
        tag: u32,
        value_address: u32,
    }

    #[repr(C)]
    struct PayloadWords {
        first: u32,
        second: u32,
    }

    #[repr(align(8))]
    struct Owner([u8; VECTOR_OFFSET + 2 * PTR]);

    impl Owner {
        fn with_vector(vtable: *const usize, begin: *mut u8, end: *mut u8) -> Self {
            let mut owner = Owner([0xa5; VECTOR_OFFSET + 2 * PTR]);
            owner.0[..PTR].copy_from_slice(&(vtable as usize).to_ne_bytes());
            owner.0[VECTOR_OFFSET..VECTOR_OFFSET + PTR]
                .copy_from_slice(&(begin as usize).to_ne_bytes());
            owner.0[VECTOR_OFFSET + PTR..VECTOR_OFFSET + 2 * PTR]
                .copy_from_slice(&(end as usize).to_ne_bytes());
            owner
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    unsafe extern "C" fn clone_from_outer(entry: *mut u8) -> *mut u8 {
        unsafe {
            CLONE_CALLS += 1;
            (*(entry as *mut OuterEntry)).clone_result
        }
    }

    unsafe extern "C" fn count_host_vector(owner: *const u8) -> i32 {
        let vector = unsafe { owner.add(VECTOR_OFFSET) };
        let begin = unsafe { (vector as *const *mut u8).read_unaligned() };
        let end = unsafe { (vector.add(PTR) as *const *mut u8).read_unaligned() };
        (end as isize - begin as isize >> 2) as i32
    }

    unsafe extern "C" fn copy_payload_words(owner_input: *mut u8, output: *mut FirstEntryPayload) {
        unsafe {
            COPY_INPUTS[COPY_CALLS] = owner_input as usize;
            COPY_CALLS += 1;
            let words = &*(owner_input as *const PayloadWords);
            (*output).first = words.first;
            (*output).second = words.second;
        }
    }

    unsafe extern "C" fn record_release(_owner: *mut u8) {
        unsafe { RELEASE_CALLS += 1 }
    }

    unsafe fn install() {
        unsafe {
            CLONE_CALLS = 0;
            COPY_INPUTS = [0; 4];
            COPY_CALLS = 0;
            RELEASE_CALLS = 0;
            RETAIL_CLONE_RESOURCE_LIST = clone_from_outer;
            HOST_VECTOR_COUNT = count_host_vector;
            HOST_COPY_FIRST_ENTRY_PAYLOAD = copy_payload_words;
        }
    }

    unsafe fn restore() {
        unsafe {
            RETAIL_CLONE_RESOURCE_LIST = missing_retail_clone_resource_list;
            HOST_VECTOR_COUNT = missing_host_vector_count;
            HOST_COPY_FIRST_ENTRY_PAYLOAD = missing_copy_first_entry_payload;
        }
    }

    #[test]
    fn scans_all_matching_lists_and_last_cros_payload_wins() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            install();
            let vtable = [0usize, record_release as usize];
            let mut first_words = PayloadWords { first: 0x1111_2222, second: 0x3333_4444 };
            let mut second_words = PayloadWords { first: 0x5555_6666, second: 0x7777_8888 };
            let mut first_owner = (&mut first_words as *mut PayloadWords).cast::<u8>();
            let mut second_owner = (&mut second_words as *mut PayloadWords).cast::<u8>();
            let mut ignored = InnerEntry {
                unused: 0,
                tag: 0x4449_4e4b,
                payload_owner: &mut first_owner,
            };
            let mut first_cros = InnerEntry {
                unused: 0,
                tag: CROS_RESOURCE_TAG,
                payload_owner: &mut first_owner,
            };
            let mut second_cros = InnerEntry {
                unused: 0,
                tag: CROS_RESOURCE_TAG,
                payload_owner: &mut second_owner,
            };
            let mut first_slots = [
                (&mut ignored as *mut InnerEntry).cast::<u8>(),
                (&mut first_cros as *mut InnerEntry).cast::<u8>(),
            ];
            let mut second_slots = [(&mut second_cros as *mut InnerEntry).cast::<u8>()];
            let first_begin = first_slots.as_mut_ptr().cast::<u8>();
            let second_begin = second_slots.as_mut_ptr().cast::<u8>();
            let mut first_list = Owner::with_vector(vtable.as_ptr(), first_begin, first_begin.add(8));
            let mut second_list = Owner::with_vector(vtable.as_ptr(), second_begin, second_begin.add(4));
            let mut first_outer = OuterEntry { unused: 0, tag: 0x1020_3040, clone_result: first_list.ptr() };
            let mut second_outer = OuterEntry { unused: 0, tag: 0x1020_3040, clone_result: second_list.ptr() };
            let mut outer_slots = [
                (&mut first_outer as *mut OuterEntry).cast::<u8>(),
                (&mut second_outer as *mut OuterEntry).cast::<u8>(),
            ];
            let outer_begin = outer_slots.as_mut_ptr().cast::<u8>();
            let mut outer_owner = Owner::with_vector(core::ptr::null(), outer_begin, outer_begin.add(8));
            let mut first_out = 0;
            let mut second_out = 0;

            resolve_tagged_cros_payload(
                core::ptr::null_mut(), outer_owner.ptr(), 2, 0x1020_3040, &mut first_out, &mut second_out,
            );

            assert_eq!((first_out, second_out), (second_words.first, second_words.second));
            assert_eq!(CLONE_CALLS, 2);
            assert_eq!(COPY_CALLS, 2);
            assert_eq!(COPY_INPUTS[..2], [first_owner as usize, second_owner as usize]);
            assert_eq!(RELEASE_CALLS, 2);
            restore();
        }
    }

    #[test]
    fn unmatched_outer_entries_leave_outputs_and_seams_untouched() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            install();
            let mut outer = OuterEntry { unused: 0, tag: 0xdead_beef, clone_result: core::ptr::null_mut() };
            let mut slots = [(&mut outer as *mut OuterEntry).cast::<u8>()];
            let begin = slots.as_mut_ptr().cast::<u8>();
            let mut owner = Owner::with_vector(core::ptr::null(), begin, begin.add(4));
            let mut first_out = 0xaaaa_5555;
            let mut second_out = 0x1234_5678;

            resolve_tagged_cros_payload(
                core::ptr::null_mut(), owner.ptr(), 1, 0x1020_3040, &mut first_out, &mut second_out,
            );

            assert_eq!((first_out, second_out), (0xaaaa_5555, 0x1234_5678));
            assert_eq!((CLONE_CALLS, COPY_CALLS, RELEASE_CALLS), (0, 0, 0));
            restore();
        }
    }

    #[test]
    fn matching_outer_without_cros_releases_list_without_writing_outputs() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            install();
            let vtable = [0usize, record_release as usize];
            let mut payload_owner = core::ptr::null_mut();
            let mut inner = InnerEntry { unused: 0, tag: 0x4449_4e4b, payload_owner: &mut payload_owner };
            let mut inner_slots = [(&mut inner as *mut InnerEntry).cast::<u8>()];
            let inner_begin = inner_slots.as_mut_ptr().cast::<u8>();
            let mut list = Owner::with_vector(vtable.as_ptr(), inner_begin, inner_begin.add(4));
            let mut outer = OuterEntry { unused: 0, tag: 0x1020_3040, clone_result: list.ptr() };
            let mut outer_slots = [(&mut outer as *mut OuterEntry).cast::<u8>()];
            let outer_begin = outer_slots.as_mut_ptr().cast::<u8>();
            let mut owner = Owner::with_vector(core::ptr::null(), outer_begin, outer_begin.add(4));
            let mut first_out = 0xa1a2_a3a4;
            let mut second_out = 0xb1b2_b3b4;

            resolve_tagged_cros_payload(
                core::ptr::null_mut(), owner.ptr(), 1, 0x1020_3040, &mut first_out, &mut second_out,
            );

            assert_eq!((first_out, second_out), (0xa1a2_a3a4, 0xb1b2_b3b4));
            assert_eq!((CLONE_CALLS, COPY_CALLS, RELEASE_CALLS), (1, 0, 1));
            restore();
        }
    }

    #[test]
    fn resolves_last_cros_indirect_value_and_releases_list() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            install();
            let Some(slab) = *INDIRECT_VALUE_FIXTURE else {
                assert!(note_missing_u32_fixture("util/tagged_resource_payload value"));
                restore();
                return;
            };
            let slab = slab as *mut u8;
            core::ptr::write_bytes(slab, 0, 0x1000);
            let first_value = slab.add(0x100).cast::<u32>();
            let second_value = slab.add(0x104).cast::<u32>();
            first_value.write(0x1122_3344);
            second_value.write(0x5566_7788);
            let ignored = slab.add(0x200).cast::<IndirectValueEntry>();
            let first_cros = slab.add(0x20c).cast::<IndirectValueEntry>();
            let second_cros = slab.add(0x218).cast::<IndirectValueEntry>();
            ignored.write(IndirectValueEntry {
                unused: 0,
                tag: 0x4449_4e4b,
                value_address: first_value as usize as u32,
            });
            first_cros.write(IndirectValueEntry {
                unused: 0,
                tag: CROS_RESOURCE_TAG,
                value_address: first_value as usize as u32,
            });
            second_cros.write(IndirectValueEntry {
                unused: 0,
                tag: CROS_RESOURCE_TAG,
                value_address: second_value as usize as u32,
            });
            let mut inner_slots = [ignored.cast::<u8>(), first_cros.cast::<u8>(), second_cros.cast::<u8>()];
            let inner_begin = inner_slots.as_mut_ptr().cast::<u8>();
            let vtable = [0usize, record_release as usize];
            let mut list = Owner::with_vector(vtable.as_ptr(), inner_begin, inner_begin.add(12));
            let mut outer = OuterEntry {
                unused: 0,
                tag: 0x1020_3040,
                clone_result: list.ptr(),
            };
            let mut outer_slots = [(&mut outer as *mut OuterEntry).cast::<u8>()];
            let outer_begin = outer_slots.as_mut_ptr().cast::<u8>();
            let mut owner = Owner::with_vector(core::ptr::null(), outer_begin, outer_begin.add(4));
            let mut value_out = 0xa1a2_a3a4;

            resolve_tagged_cros_value(
                core::ptr::null_mut(), owner.ptr(), 1, 0x1020_3040, &mut value_out,
            );

            assert_eq!(value_out, 0x5566_7788);
            assert_eq!((CLONE_CALLS, RELEASE_CALLS), (1, 1));
            restore();
        }
    }

    #[test]
    fn missing_cros_leaves_value_untouched_after_releasing_match() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            install();
            let Some(slab) = *INDIRECT_VALUE_FIXTURE else {
                assert!(note_missing_u32_fixture("util/tagged_resource_payload value"));
                restore();
                return;
            };
            let slab = slab as *mut u8;
            core::ptr::write_bytes(slab, 0, 0x1000);
            let ignored = slab.add(0x200).cast::<IndirectValueEntry>();
            ignored.write(IndirectValueEntry {
                unused: 0,
                tag: 0x4449_4e4b,
                value_address: 0,
            });
            let mut inner_slots = [ignored.cast::<u8>()];
            let inner_begin = inner_slots.as_mut_ptr().cast::<u8>();
            let vtable = [0usize, record_release as usize];
            let mut list = Owner::with_vector(vtable.as_ptr(), inner_begin, inner_begin.add(4));
            let mut outer = OuterEntry {
                unused: 0,
                tag: 0x1020_3040,
                clone_result: list.ptr(),
            };
            let mut outer_slots = [(&mut outer as *mut OuterEntry).cast::<u8>()];
            let outer_begin = outer_slots.as_mut_ptr().cast::<u8>();
            let mut owner = Owner::with_vector(core::ptr::null(), outer_begin, outer_begin.add(4));
            let mut value_out = 0xa1a2_a3a4;

            resolve_tagged_cros_value(
                core::ptr::null_mut(), owner.ptr(), 1, 0x1020_3040, &mut value_out,
            );

            assert_eq!(value_out, 0xa1a2_a3a4);
            assert_eq!((CLONE_CALLS, RELEASE_CALLS), (1, 1));
            restore();
        }
    }
}

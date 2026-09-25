//! Copy construction for the unidentified three-word records used by the
//! `0x083eXXXX` vector helpers.
//!
//! The record is a [`StringObject`] followed by one opaque 32-bit value. The
//! `0x08177604` caller builds these records from a StringObject and list index;
//! the `0x083eXXXX` callers copy them while growing and rearranging vectors.
//! No concrete class identity is established, so its name describes its layout.

use crate::cxx::string_object::{
    string_object_assign, string_object_copy_construct, StringObject,
};

/// A StringObject followed by the opaque word its copy constructor preserves.
///
/// On ARMv5TE this is 12 bytes: the embedded StringObject at +0 and `value` at
/// +8. `repr(C)` and named fields preserve that layout without applying
/// 32-bit byte offsets to widened host pointers.
#[repr(C)]
pub struct StringWordRecord {
    pub string: StringObject,
    pub value: u32,
}

/// string_word_record_copy_construct — original: `FUN_081f4ffc` @
/// `0x081f4ffc` (24 bytes, six ARM words; the next separately linked function
/// starts at `0x081f5014`). **9 direct `bl` call sites** verified by decoding
/// every ARM `B`/`BL` word in `work/firmware/osos.dec`: four unconditional
/// (`0x083e82a4`, `0x083e82f4`, `0x083e97f8`, `0x083eaa10`) and five `blne`
/// (`0x0817770c`, `0x083e1870`, `0x083e1900`, `0x083e80b0`, `0x083e8b58`).
///
/// Copy-constructs the embedded [`StringObject`] at +0 through the ported
/// [`string_object_copy_construct`] @ `0x082773e0`, then copies the opaque
/// source word at +8 to the destination at +8. It returns the embedded
/// constructor's result, which is the record address because that subobject is
/// first. The function itself has no NULL guard; its five predicated callers
/// gate the call before entering, while four callers enter unconditionally.
///
/// Deliberate deviations: none. The original's +8 accesses use the named
/// `value` field so the 32-bit ARM layout does not overlap widened host pointer
/// fields.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_word_record_copy_construct(
    this: *mut StringWordRecord,
    source: *const StringWordRecord,
) -> *mut StringWordRecord {
    string_object_copy_construct(
        core::ptr::addr_of_mut!((*this).string),
        core::ptr::addr_of!((*source).string),
    );
    (*this).value = (*source).value;
    this
}

/// string_word_record_uninitialized_copy — original: `FUN_083e8b3c` @
/// `0x083e8b3c` (56 bytes, fourteen ARM words; the next separately linked
/// function starts with `push {lr}` at `0x083e8b74`). **2 direct `bl` call
/// sites** verified by decoding every ARM `B`/`BL` word in
/// `work/firmware/osos.dec`: two unconditional (`0x083e18e0`, `0x083e192c`)
/// and zero predicated inbound calls. The body has one predicated `blne` to
/// [`string_word_record_copy_construct`] @ `0x081f4ffc`.
///
/// Copy-constructs the records in `[first, last)` at `output`, advancing both
/// cursors by one 12-byte target record each iteration, and returns the final
/// output cursor. The ARM tests the current output cursor each iteration:
/// a NULL cursor skips that construction before advancing by 12.
///
/// Deliberate deviation: Rust advances typed cursors by [`StringWordRecord`].
/// This maps to 12 bytes on ARM and the widened host record stride in tests.
///
/// # Safety
///
/// `first..last` must be a valid forward range of [`StringWordRecord`]s.
/// Every non-NULL output cursor reached by the loop must designate valid
/// uninitialized storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_word_record_uninitialized_copy(
    mut first: *const StringWordRecord,
    last: *const StringWordRecord,
    mut output: *mut StringWordRecord,
) -> *mut StringWordRecord {
    while first != last {
        if !output.is_null() {
            string_word_record_copy_construct(output, first);
        }
        first = first.add(1);
        output = output.wrapping_add(1);
    }
    output
}

/// string_word_record_copy_assign — original: `FUN_081f5014` @
/// `0x081f5014` (32 bytes, eight ARM words; the next separately linked
/// function starts with `push {r4,lr}` at `0x081f5034`). Whole-image raw A32
/// decoding finds **3 inbound plain `bl` call sites** (`0x083e8140`,
/// `0x083e87d4`, `0x083e87f0`) and zero predicated inbound BL forms. The body
/// has one plain BL to `string_object_assign` @ `0x082774a8` and no predicated
/// calls.
///
/// ```text
/// push {r4, r5, r6, lr}
/// mov  r5, r1          ; save source
/// mov  r4, r0          ; save this
/// bl   0x082774a8      ; string_object_assign(this, source)
/// ldr  r0, [r5, #8]    ; source->value
/// str  r0, [r4, #8]    ; this->value
/// mov  r0, r4          ; return this
/// pop  {r4, r5, r6, pc}
/// ```
///
/// The record class's copy-assignment operator reassigns the embedded
/// [`StringObject`] through [`string_object_assign`], then copies the opaque
/// word at +8. It returns `this` unconditionally. Deliberate deviations:
/// none; `repr(C)` fields express the ARM +0 and +8 accesses without applying
/// target byte offsets to widened host pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_word_record_copy_assign(
    this: *mut StringWordRecord,
    source: *const StringWordRecord,
) -> *mut StringWordRecord {
    string_object_assign(
        core::ptr::addr_of_mut!((*this).string),
        core::ptr::addr_of!((*source).string),
    );
    (*this).value = (*source).value;
    this
}

/// string_word_record_copy_backward — original: `FUN_083e811c` @
/// `0x083e811c` (56 bytes; the next separately linked function starts with
/// `push {r4, r5, r6, lr}` at `0x083e8154`, binary-verified). **4 direct
/// `bl` call sites** (`0x083e1880`, `0x083e82cc`, `0x083e869c`,
/// `0x083e86e8`), verified by decoding every ARM `B`/`BL` word in
/// osos.dec; no predicated calls. Ghidra's "4 bl" report is these inbound
/// sites — the body itself contains exactly one `bl`, to `FUN_081f5014`.
///
/// Decoded from the raw ARM:
///
/// ```text
/// push {r4, r5, r6, lr}
/// mov  r6, r0          ; first
/// mov  r5, r2          ; dest cursor
/// mov  r4, r1          ; source cursor
/// b    test
/// loop:
/// sub  r1, r4, #0xc
/// sub  r0, r5, #0xc
/// mov  r5, r0
/// mov  r4, r1
/// bl   0x081f5014      ; record copy-assign(dest, source)
/// test:
/// cmp  r6, r4
/// bne  loop
/// mov  r0, r5
/// pop  {r4, r5, r6, pc}
/// ```
///
/// `std::copy_backward` over the record range `[first, last)`: records are
/// assigned highest-address-first into the destination range ending at
/// `result_end`, which is what makes an in-place shift to a higher address
/// (the vector gap-opening move) safe. Returns the new destination start,
/// `result_end - (last - first)`; for an empty range nothing is touched
/// and `result_end` is returned.
///
/// Deliberate deviations: the loop steps whole [`StringWordRecord`]
/// strides instead of the literal `0xc` so widened host pointers keep the
/// 12-byte ARM layout semantics. Its per-record call targets the separately
/// exported [`string_word_record_copy_assign`] port directly. No behavioral
/// difference.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_word_record_copy_backward(
    first: *const StringWordRecord,
    last: *const StringWordRecord,
    result_end: *mut StringWordRecord,
) -> *mut StringWordRecord {
    let mut source = last;
    let mut dest = result_end;
    while first != source {
        source = source.sub(1);
        dest = dest.sub(1);
        string_word_record_copy_assign(dest, source);
    }
    dest
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, StringObjectVtable, DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS,
        STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_VTABLE,
    };
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;
    use core::mem::MaybeUninit;
    use std::sync::MutexGuard;

    static mut COPY_ALLOCATION: Option<(usize, usize, u32)> = None;
    static mut COPY_STORAGE: [u8; 16] = [0; 16];

    unsafe extern "C" fn record_copy_allocation(
        this: *mut StringObject,
        requested_size: usize,
        flags: u32,
    ) -> *mut u8 {
        core::ptr::addr_of_mut!(COPY_ALLOCATION).write(Some((
            this as usize,
            requested_size,
            flags,
        )));
        let storage = core::ptr::addr_of_mut!(COPY_STORAGE).cast::<u8>();
        (*this).payload = storage;
        storage
    }

    unsafe extern "C" fn record_copy_clear(_this: *mut StringObject) {}

    /// Restores the shared virtual assignment seam if a test assertion panics.
    struct CopyAssignOpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for CopyAssignOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS)
                    .write_volatile(DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS);
            }
        }
    }

    fn copy_assign_bench() -> CopyAssignOpsGuard {
        let lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(COPY_ALLOCATION).write(None);
            core::ptr::addr_of_mut!(COPY_STORAGE).write([0; 16]);
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(
                StringObjectAssignCstrOps {
                    allocate_payload: record_copy_allocation,
                    clear_payload: record_copy_clear,
                },
            );
        }
        CopyAssignOpsGuard { _lock: lock }
    }

    #[test]
    fn copies_the_embedded_string_and_trailing_word() {
        let _bench = copy_assign_bench();
        let mut source_text = *b"edge\0";
        let source = StringWordRecord {
            string: StringObject {
                vtable: 0xdead_beefusize as *const StringObjectVtable,
                payload: source_text.as_mut_ptr(),
            },
            value: u32::MAX,
        };
        let mut destination = MaybeUninit::<StringWordRecord>::uninit();
        let destination_ptr = destination.as_mut_ptr();

        unsafe {
            assert_eq!(
                string_word_record_copy_construct(destination_ptr, &source),
                destination_ptr
            );
            let destination = destination.assume_init();
            assert_eq!(destination.string.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert_eq!(destination.string.payload, core::ptr::addr_of_mut!(COPY_STORAGE).cast());
            assert_eq!(&COPY_STORAGE[..5], b"edge\0");
            assert_eq!(destination.value, u32::MAX);
            assert_eq!(
                COPY_ALLOCATION,
                Some((
                    core::ptr::addr_of_mut!((*destination_ptr).string) as usize,
                    5,
                    0,
                ))
            );
        }
    }

    #[test]
    fn self_copy_preserves_payload_without_allocating() {
        let _bench = copy_assign_bench();
        let mut source_text = *b"same\0";
        let mut record = StringWordRecord {
            string: StringObject {
                vtable: 0xdead_beefusize as *const StringObjectVtable,
                payload: source_text.as_mut_ptr(),
            },
            value: 0x89ab_cdef,
        };
        let record_ptr: *mut StringWordRecord = &mut record;

        unsafe {
            assert_eq!(string_word_record_copy_construct(record_ptr, record_ptr), record_ptr);
            assert_eq!(record.string.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert_eq!(record.string.payload, source_text.as_mut_ptr());
            assert_eq!(record.value, 0x89ab_cdef);
            assert_eq!(COPY_ALLOCATION, None);
        }
    }

    #[test]
    fn copy_assign_reassigns_the_string_and_copies_the_opaque_word() {
        let _bench = copy_assign_bench();
        let mut source_text = *b"assign\0";
        let source = StringWordRecord {
            string: StringObject {
                vtable: 0xdead_beefusize as *const StringObjectVtable,
                payload: source_text.as_mut_ptr(),
            },
            value: u32::MAX,
        };
        let mut destination = StringWordRecord {
            string: StringObject {
                vtable: 0xdead_beefusize as *const StringObjectVtable,
                payload: core::ptr::null_mut(),
            },
            value: 0,
        };

        unsafe {
            let destination_ptr: *mut StringWordRecord = &mut destination;
            assert_eq!(string_word_record_copy_assign(destination_ptr, &source), destination_ptr);
            assert_eq!(destination.string.payload, core::ptr::addr_of_mut!(COPY_STORAGE).cast());
            assert_eq!(&COPY_STORAGE[..7], b"assign\0");
            assert_eq!(destination.value, u32::MAX);
            assert_eq!(
                COPY_ALLOCATION,
                Some((
                    core::ptr::addr_of_mut!(destination.string) as usize,
                    7,
                    0,
                ))
            );
        }
    }

    /// Per-assignment destination buffers handed out by the recording
    /// allocate op, so each copied record owns observable payload storage.
    static mut BACKWARD_POOL: [[u8; 16]; 8] = [[0; 16]; 8];
    static mut BACKWARD_CURSOR: usize = 0;
    /// `(this, requested_size, pool_slot)` per allocation, in call order.
    static mut BACKWARD_ALLOCATIONS: std::vec::Vec<(usize, usize, usize)> = std::vec::Vec::new();

    unsafe extern "C" fn backward_copy_allocation(
        this: *mut StringObject,
        requested_size: usize,
        _flags: u32,
    ) -> *mut u8 {
        let cursor = core::ptr::addr_of_mut!(BACKWARD_CURSOR).read();
        core::ptr::addr_of_mut!(BACKWARD_CURSOR).write(cursor + 1);
        let storage = core::ptr::addr_of_mut!(BACKWARD_POOL[cursor]).cast::<u8>();
        (*this).payload = storage;
        core::ptr::addr_of_mut!(BACKWARD_ALLOCATIONS)
            .as_mut()
            .unwrap()
            .push((this as usize, requested_size, cursor));
        storage
    }

    unsafe extern "C" fn backward_copy_clear(_this: *mut StringObject) {}

    /// Installs the recording ops over the shared seam and resets the pool.
    fn backward_bench() -> CopyAssignOpsGuard {
        let bench = copy_assign_bench();
        unsafe {
            core::ptr::addr_of_mut!(BACKWARD_CURSOR).write(0);
            core::ptr::addr_of_mut!(BACKWARD_ALLOCATIONS)
                .as_mut()
                .unwrap()
                .clear();
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(
                StringObjectAssignCstrOps {
                    allocate_payload: backward_copy_allocation,
                    clear_payload: backward_copy_clear,
                },
            );
        }
        bench
    }

    fn record(text: &mut [u8], value: u32) -> StringWordRecord {
        StringWordRecord {
            string: StringObject {
                vtable: 0xdead_beefusize as *const StringObjectVtable,
                payload: text.as_mut_ptr(),
            },
            value,
        }
    }

    /// Three 16-byte text buffers, `b"a\0"`, `b"bb\0"`, `b"ccc\0"`,
    /// returned with their lengths.
    fn backward_texts() -> ([[u8; 16]; 3], [usize; 3]) {
        let mut texts = [[0u8; 16]; 3];
        texts[0][..2].copy_from_slice(b"a\0");
        texts[1][..3].copy_from_slice(b"bb\0");
        texts[2][..4].copy_from_slice(b"ccc\0");
        (texts, [2, 3, 4])
    }

    #[test]
    fn copy_backward_assigns_highest_first_and_returns_the_new_start() {
        let _bench = backward_bench();
        let (mut texts, lens) = backward_texts();
        let mut sources = [
            record(&mut texts[0], 0x1111_1111),
            record(&mut texts[1], 0x2222_2222),
            record(&mut texts[2], u32::MAX),
        ];
        let mut destinations = [
            record(&mut [], 0),
            record(&mut [], 0),
            record(&mut [], 0),
        ];

        unsafe {
            let first = sources.as_ptr();
            let last = sources.as_ptr().add(3);
            let result_end = destinations.as_mut_ptr().add(3);
            let returned = string_word_record_copy_backward(first, last, result_end);

            assert_eq!(returned, destinations.as_mut_ptr());
            let allocations = (*core::ptr::addr_of!(BACKWARD_ALLOCATIONS)).clone();
            assert_eq!(allocations.len(), 3);
            assert_eq!(
                allocations.iter().map(|&(this, ..)| this).collect::<std::vec::Vec<_>>(),
                std::vec![
                    core::ptr::addr_of_mut!((*destinations.as_mut_ptr().add(2)).string) as usize,
                    core::ptr::addr_of_mut!((*destinations.as_mut_ptr().add(1)).string) as usize,
                    core::ptr::addr_of_mut!((*destinations.as_mut_ptr().add(0)).string) as usize,
                ],
                "assignments run highest-address-first"
            );
            assert_eq!(
                allocations.iter().map(|&(_, size, _)| size).collect::<std::vec::Vec<_>>(),
                std::vec![4, 3, 2],
                "strlen + 1 of \"ccc\", \"bb\", \"a\""
            );
            for index in 0..3 {
                let slot = allocations[2 - index].2;
                assert_eq!(
                    &BACKWARD_POOL[slot][..lens[index]],
                    &texts[index][..lens[index]],
                    "record {index} payload text copied through the assignment"
                );
                assert_eq!(destinations[index].value, sources[index].value);
            }
        }
    }

    #[test]
    fn copy_backward_empty_range_touches_nothing_and_returns_result_end() {
        let _bench = backward_bench();
        let mut text = *b"edge\0";
        let mut records = [record(&mut text, 7)];

        unsafe {
            let boundary = records.as_mut_ptr().add(1);
            let returned =
                string_word_record_copy_backward(boundary, boundary, records.as_mut_ptr());
            assert_eq!(returned, records.as_mut_ptr());
            assert!((*core::ptr::addr_of!(BACKWARD_ALLOCATIONS)).is_empty());
            assert_eq!(records[0].value, 7, "no record is written for an empty range");
        }
    }

    #[test]
    fn copy_backward_shifts_an_overlapping_range_up_in_place() {
        let _bench = backward_bench();
        let (mut texts, _) = backward_texts();
        let mut records = [
            record(&mut texts[0], 0xaaaa),
            record(&mut texts[1], 0xbbbb),
            record(&mut texts[2], 0xcccc),
            record(&mut [], 0xdddd),
        ];

        unsafe {
            let base = records.as_mut_ptr();
            let returned = string_word_record_copy_backward(base, base.add(3), base.add(4));
            assert_eq!(returned, base.add(1));
            assert_eq!(records[1].value, 0xaaaa);
            assert_eq!(records[2].value, 0xbbbb);
            assert_eq!(records[3].value, 0xcccc);
            let allocations = (*core::ptr::addr_of!(BACKWARD_ALLOCATIONS)).clone();
            assert_eq!(allocations.len(), 3);
            assert_eq!(
                allocations.iter().map(|&(_, size, _)| size).collect::<std::vec::Vec<_>>(),
                std::vec![4, 3, 2],
                "highest record is moved before the lower ones it would overlap"
            );
        }
    }

    #[test]
    fn uninitialized_copy_constructs_each_record_and_returns_end() {
        let _bench = copy_assign_bench();
        let mut first_text = *b"one\0";
        let mut second_text = *b"two\0";
        let source = [
            record(&mut first_text, 0x1111_2222),
            record(&mut second_text, 0x3333_4444),
        ];
        let mut output: [MaybeUninit<StringWordRecord>; 2] =
            core::array::from_fn(|_| MaybeUninit::uninit());

        unsafe {
            let returned = string_word_record_uninitialized_copy(
                source.as_ptr(),
                source.as_ptr().add(2),
                output.as_mut_ptr().cast(),
            );
            assert_eq!(returned, output.as_mut_ptr().cast::<StringWordRecord>().add(2));
            assert_eq!(output[0].assume_init_read().value, 0x1111_2222);
            assert_eq!(output[1].assume_init_read().value, 0x3333_4444);
            assert_eq!(&COPY_STORAGE[..4], b"two\0");
        }
    }

    #[test]
    fn uninitialized_copy_empty_range_does_not_construct() {
        let _bench = copy_assign_bench();
        let mut text = *b"edge\0";
        let source = [record(&mut text, 7)];
        let mut output = MaybeUninit::<StringWordRecord>::uninit();

        unsafe {
            let boundary = source.as_ptr().add(1);
            assert_eq!(
                string_word_record_uninitialized_copy(boundary, boundary, output.as_mut_ptr()),
                output.as_mut_ptr()
            );
            assert_eq!(COPY_ALLOCATION, None);
        }
    }

    #[test]
    fn uninitialized_copy_null_output_skips_first_construction_then_advances() {
        let _bench = copy_assign_bench();
        let mut text = *b"one\0";
        let source = [record(&mut text, 1)];

        unsafe {
            assert_eq!(
                string_word_record_uninitialized_copy(
                    source.as_ptr(),
                    source.as_ptr().add(1),
                    core::ptr::null_mut(),
                ) as usize,
                core::mem::size_of::<StringWordRecord>()
            );
            assert_eq!(COPY_ALLOCATION, None);
        }
    }
}

//! Clear an owner's word vector and dispatch it to its render context.
//!
//! `coordinate_owner_clear_words` — `FUN_0828d57c` at **0x0828d57c**.
//! Raw extent: 120 bytes, ending before the distinct prologue at 0x0828d5f4.
//! Two incoming plain BL calls (0x081576b4, 0x081586d8), zero predicated
//! BL calls; the body has no BL and one conditional indirect tail BX.
//!
//! The owner stores a word vector at +0x14 and a context at +0x78. Reset
//! the vector end to its begin, preserving capacity and backing words.
//! If the context exists, invoke its vtable +0xf4 method with the context
//! and vector address. The virtual callee's identity is not assumed.
//!
//! Deliberate deviations: omit the original never-entered copy loop and
//! empty word traversal. Valid vectors have aligned begin/end pointers in
//! the same allocation; malformed vectors that would hang are outside the
//! contract. A Rust indirect call replaces the tail BX. repr(C) pointer
//! fields retain the retail layout on ARM and widen naturally on hosts.

use core::ptr;

#[repr(C)]
pub struct OwnerWordVector {
    pub begin: *mut u32,
    pub end: *mut u32,
    pub capacity_end: *mut u32,
}

#[repr(C)]
pub struct WordVectorRenderContext {
    pub vtable: *const WordVectorRenderVtable,
}

#[repr(C)]
pub struct WordVectorRenderVtable {
    pub preceding_slots: [usize; 61],
    pub dispatch_words: unsafe extern "C" fn(*mut WordVectorRenderContext, *mut OwnerWordVector),
}

#[repr(C)]
pub struct CoordinateWordOwner {
    pub prefix: [u32; 5],
    pub words: OwnerWordVector,
    pub intervening_words: [u32; 22],
    pub context: *mut WordVectorRenderContext,
}

/// # Safety
/// `owner` must be writable and contain a valid aligned word vector. A
/// non-null context must expose a live vtable and a compatible +0xf4 method.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn coordinate_owner_clear_words(owner: *mut CoordinateWordOwner) {
    unsafe {
        let words = ptr::addr_of_mut!((*owner).words);
        let begin = ptr::addr_of!((*words).begin).read();
        if begin != ptr::addr_of!((*words).end).read() {
            ptr::addr_of_mut!((*words).end).write(begin);
        }
        let context = ptr::addr_of!((*owner).context).read();
        if !context.is_null() {
            let vtable = ptr::addr_of!((*context).vtable).read();
            ((*vtable).dispatch_words)(context, words);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct RecordingContext {
        base: WordVectorRenderContext,
        calls: usize,
        observed: *mut OwnerWordVector,
        expected_begin: *mut u32,
    }

    unsafe extern "C" fn consume_words(context: *mut WordVectorRenderContext, words: *mut OwnerWordVector) {
        unsafe {
            let record = &mut *context.cast::<RecordingContext>();
            assert_eq!((*words).begin, record.expected_begin);
            assert_eq!((*words).end, record.expected_begin);
            record.calls += 1;
            record.observed = words;
            // A callee may repopulate the vector; the caller must not clear again.
            (*words).end = (*words).capacity_end;
        }
    }

    fn owner(data: &mut [u32; 4], count: usize) -> CoordinateWordOwner {
        CoordinateWordOwner {
            prefix: [0x12345678; 5],
            words: OwnerWordVector {
                begin: data.as_mut_ptr(),
                end: unsafe { data.as_mut_ptr().add(count) },
                capacity_end: unsafe { data.as_mut_ptr().add(4) },
            },
            intervening_words: [0x87654321; 22],
            context: ptr::null_mut(),
        }
    }

    #[test]
    fn clears_empty_partial_and_full_vectors_without_touching_storage() {
        for count in [0, 1, 4] {
            let mut data = [11, 22, 33, 44];
            let mut owner = owner(&mut data, count);
            unsafe { coordinate_owner_clear_words(&mut owner) };
            assert_eq!(owner.words.end, owner.words.begin);
            assert_eq!(owner.words.capacity_end, unsafe { data.as_mut_ptr().add(4) });
            assert_eq!(data, [11, 22, 33, 44]);
            assert_eq!(owner.prefix, [0x12345678; 5]);
            assert_eq!(owner.intervening_words, [0x87654321; 22]);
        }
    }

    #[test]
    fn dispatches_even_empty_vectors_after_clear_and_preserves_callee_changes() {
        let vtable = WordVectorRenderVtable { preceding_slots: [0; 61], dispatch_words: consume_words };
        for count in [0, 1, 4] {
            let mut data = [11, 22, 33, 44];
            let mut owner = owner(&mut data, count);
            let mut context = RecordingContext {
                base: WordVectorRenderContext { vtable: &vtable },
                calls: 0,
                observed: ptr::null_mut(),
                expected_begin: data.as_mut_ptr(),
            };
            owner.context = &mut context.base;
            unsafe { coordinate_owner_clear_words(&mut owner) };
            assert_eq!(context.calls, 1);
            assert_eq!(context.observed, ptr::addr_of_mut!(owner.words));
            assert_eq!(owner.words.end, owner.words.capacity_end);
            assert_eq!(data, [11, 22, 33, 44]);
        }
    }

    #[test]
    fn null_empty_vector_needs_no_backing_allocation() {
        let mut data = [0; 4];
        let mut owner = owner(&mut data, 0);
        owner.words = OwnerWordVector {
            begin: ptr::null_mut(), end: ptr::null_mut(), capacity_end: ptr::null_mut(),
        };
        unsafe { coordinate_owner_clear_words(&mut owner) };
        assert!(owner.words.end.is_null());
    }
}

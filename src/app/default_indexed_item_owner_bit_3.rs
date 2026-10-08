use core::mem::MaybeUninit;
use super::scoped_context::{
    IndexedContextSource, ScopedContext, indexed_item_context_construct,
    scoped_context_destroy, scoped_context_owner_byte_8f_bit_3,
};

/// Default indexed item owner bit 3 — retail `FUN_08112d08` @ 0x08112d08.
/// True extent: 84 bytes, [0x08112d08, 0x08112d5c), followed by a separate
/// push. Verified: two incoming plain BLs, five outgoing plain BLs, zero
/// predicated BLs in either direction.
///
/// Constructs a query with id/mode zero, constructs its indexed context,
/// reads validity-gated owner byte +0x8f bit 3, destroys context then query,
/// and returns the saved 0-or-1 result. The receiver is deliberately unused.
/// Deviations: native repr(C) source/context pointers widen on hosts; the
/// unported query constructor uses its existing firmware seam. The empty
/// context destructor may be optimized out. No callee identity is guessed.
///
/// # Safety
/// Firmware globals and selected item storage must satisfy the query and
/// indexed-context constructors' contracts. The receiver is never read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn default_indexed_item_owner_bit_3(
    _receiver: *const u8, index: i32,
) -> u32 {
    evaluate(index,
        |query| { crate::fp::fp_misc::query_object_construct(query.cast(), 0, 0); },
        |query| { crate::fp::fp_misc::query_object_destroy_port(query.cast()); },
    )
}

#[inline(always)]
unsafe fn evaluate(
    index: i32,
    construct: impl FnOnce(*mut IndexedContextSource),
    destroy: impl FnOnce(*mut IndexedContextSource),
) -> u32 {
    // This type occupies the original 72-byte query allocation on ARM,
    // including the constructor's mode byte at +0x45 in trailing padding.
    let mut query = MaybeUninit::<IndexedContextSource>::uninit();
    construct(query.as_mut_ptr());
    let mut context = MaybeUninit::<ScopedContext>::uninit();
    indexed_item_context_construct(context.as_mut_ptr(), query.as_ptr(), index);
    let result = scoped_context_owner_byte_8f_bit_3(context.as_ptr());
    scoped_context_destroy(context.as_mut_ptr());
    destroy(query.as_mut_ptr());
    result
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::size_of::<IndexedContextSource>() == 72);

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::scoped_context::{
        IndexedContextCollection, ScopedContextVtable, CAPTURE_CONTEXT_FIELDS,
    };
    use core::ptr;

    unsafe extern "C" fn owner_present(context: *const ScopedContext) -> u32 {
        u32::from(!(*context).owner.is_null())
    }
    static mut VTABLE: ScopedContextVtable = ScopedContextVtable { slots: [0; 15] };
    unsafe extern "C" fn capture(context: *mut ScopedContext, owner: *mut u8) {
        (*context).owner = owner;
        (*context).vtable = ptr::addr_of!(VTABLE);
    }
    struct Restore(unsafe extern "C" fn(*mut ScopedContext, *mut u8));
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { ptr::addr_of_mut!(CAPTURE_CONTEXT_FIELDS).write(self.0); } }
    }

    #[test]
    fn default_indexed_bit_handles_boundaries_availability_and_saved_result() {
        let _lock = crate::testing::APP_ROOT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            (*ptr::addr_of_mut!(VTABLE)).slots[2] = owner_present as *const () as usize;
            let _restore = Restore(ptr::addr_of!(CAPTURE_CONTEXT_FIELDS).read());
            ptr::addr_of_mut!(CAPTURE_CONTEXT_FIELDS).write(capture);
            let Some(slab) = crate::testing::try_map_u32_slab(
                crate::testing::hints::DEFAULT_INDEXED_ITEM_OWNER_BIT_3, 0x1000,
            ) else {
                assert!(crate::testing::note_missing_u32_fixture("default indexed owner bit"));
                return;
            };
            ptr::write_bytes(slab, 0, 0x1000);
            let owner = slab.add(0x100);
            let item = slab;
            item.add(0x20).cast::<u32>().write(owner as usize as u32);
            let items = [item as *const u8];
            let collection = IndexedContextCollection {
                preceding_words: [0; 0xeec / 4], items: items.as_ptr(),
                intervening_word: 0, count: 1,
            };
            for index in [i32::MIN, -1, 0, 1, i32::MAX] {
                for unavailable in [0, 1] {
                    item.add(0x1d).write(unavailable);
                    for byte in [0, 1, 7, 8, 0x80, 0xf7, 0xff] {
                        owner.add(0x8f).write(byte);
                        let result = evaluate(index, |query| {
                            query.write(IndexedContextSource {
                                preceding_words: [0; 16], collection: &collection, mode: 0,
                            });
                        }, |_| {
                            // Cleanup must not change the already-saved result.
                            owner.add(0x8f).write(byte ^ 8);
                        });
                        let expected = if index == 0 && unavailable == 0 { (byte & 8) >> 3 } else { 0 };
                        assert_eq!(result, u32::from(expected), "index {index}, flag {unavailable}, byte {byte:#x}");
                    }
                }
            }
        }
    }
}

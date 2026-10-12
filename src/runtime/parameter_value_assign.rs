//! Parameter value replacement — FUN_0803a55c @ 0x0803a55c.
//! True extent: 48 bytes, [0x0803a55c, 0x0803a58c). Outbound: zero
//! plain BL, one BLNE to parameter_value_destroy; inbound: one BL, one BLNE.
//! If the old value word is nonzero, destroy it through an indirect header
//! slot with a NULL descriptor. Then store the supplied type and value words.
//! Deviations: omit unused stack copies of the new words; the temporary
//! indirect slot retains the firmware's u32 pointer representation on hosts.

use super::parameter_value_destroy::parameter_value_destroy;

/// # Safety
/// `header` must point to two aligned writable u32 words and fit in a u32
/// address. Its nonzero old value must satisfy parameter_value_destroy's
/// contract for the old type. The replacement is stored verbatim, not copied.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parameter_value_assign(header: *mut u32, value_type: u32, value: u32) {
    if header.add(1).read() != 0 {
        let mut slot = header as usize as u32;
        parameter_value_destroy(&mut slot, core::ptr::null());
    }
    header.write(value_type);
    header.add(1).write(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS};
    use crate::heap::owned_buffer::OwnedBuffer;
    static mut HEADER: *mut u32 = core::ptr::null_mut();
    static mut FREED: [usize; 2] = [0; 2];
    static mut FREE_COUNT: usize = 0;
    unsafe extern "C" fn free(block: *mut u8) {
        // Both releases must happen while the old header is still installed.
        assert_eq!(HEADER.read(), 2);
        assert_ne!(HEADER.add(1).read(), 0);
        (*core::ptr::addr_of_mut!(FREED))[FREE_COUNT] = block as usize;
        FREE_COUNT += 1;
    }

    #[test]
    fn replacement_preserves_boundaries_and_destroys_old_owned_value_first() {
        let _lock = match crate::testing::TRACED_ALLOC_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(error) => panic!("allocator fixture lock poisoned: {error}"),
        };
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PARAMETER_VALUE_ASSIGN, 4096,
        ) else { return; };
        unsafe {
            let words = slab.cast::<u32>();
            let header = words.add(1);
            words.write(0x12345678);
            words.add(3).write(0x87654321);
            // A zero value bypasses destruction even for an owning/unknown type.
            for old_type in [0, 2, 6, u32::MAX, (-4i32) as u32] {
                header.write(old_type);
                header.add(1).write(0);
                parameter_value_assign(header, u32::MAX, 0xdeadbeef);
                assert_eq!([header.read(), header.add(1).read()], [u32::MAX, 0xdeadbeef]);
            }
            // Borrowed values and scalar values are replaced without freeing.
            for old_type in [1, 5] {
                header.write(old_type);
                header.add(1).write(0xabcdef01);
                parameter_value_assign(header, 0, 0);
                assert_eq!([header.read(), header.add(1).read()], [0, 0]);
            }
            let owner = slab.add(64).cast::<OwnedBuffer>();
            let data = slab.add(128);
            owner.write(OwnedBuffer { length: 3, source: 2, data, context: 0 });
            header.write(2);
            header.add(1).write(owner as usize as u32);
            HEADER = header;
            FREE_COUNT = 0;
            FREED = [0; 2];
            let old = core::ptr::read(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            TRACED_FREE_HOOKS = TracedFreeHooks { free, trace: None };
            parameter_value_assign(header, 5, 0xfedcba98);
            TRACED_FREE_HOOKS = old;
            assert_eq!(FREE_COUNT, 2);
            assert_eq!(*core::ptr::addr_of!(FREED), [data as usize, owner as usize]);
            assert_eq!([header.read(), header.add(1).read()], [5, 0xfedcba98]);
            assert_eq!(words.read(), 0x12345678);
            assert_eq!(words.add(3).read(), 0x87654321);
        }
    }
}

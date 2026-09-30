//! OpenSSL ASN.1 sequence reference counting.
//!
//! `asn1_do_ref` — `FUN_082b4bc4` @ 0x082b4bc4, 96 bytes through
//! 0x082b4c20; next real function begins at 0x082b4c24. Raw ARM verifies
//! two plain inbound BLs (0x080c8728, 0x080d3c0c), no predicated inbound
//! BLs, and one plain outbound BL to `crypto_add_lock` @ 0x08043828,
//! with no predicated outbound BLs.
//!
//! Sequence kind 1 with auxiliary flag bit 0 supports a reference count
//! at the auxiliary byte offset in the containing value. Amount zero
//! initializes it to one without locking; other amounts use the auxiliary
//! lock type and return `crypto_add_lock`'s result. Unsupported items return
//! zero before reading the value slot.
//!
//! Deliberate deviations: pointers in descriptors remain u32 words for
//! ARM layout on hosts; address addition wraps explicitly. The BL uses the
//! existing Rust port and its services-descriptor hook table.

use crate::crypto::add_lock::crypto_add_lock;

/// # Safety
/// `item` must provide its kind byte and, for kind 1, auxiliary word 4.
/// Non-NULL auxiliary data must provide flags, offset, and lock type at
/// words 1..3. For enabled reference counting, `value_slot` must contain
/// a target-width address whose wrapping sum with the offset denotes an
/// aligned writable i32. No extra NULL guards are introduced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn asn1_do_ref(value_slot: *const u32, amount: i32, item: *const u32) -> i32 {
    if unsafe { item.cast::<u8>().read() } != 1 {
        return 0;
    }
    let auxiliary = unsafe { item.add(4).read() } as usize as *const u32;
    if auxiliary.is_null() || unsafe { auxiliary.add(1).read() } & 1 == 0 {
        return 0;
    }
    let count = unsafe { value_slot.read().wrapping_add(auxiliary.add(2).read()) }
        as usize as *mut i32;
    if amount == 0 {
        unsafe { count.write(1) };
        return 1;
    }
    let lock_type = unsafe { auxiliary.add(3).read() } as i32;
    unsafe { crypto_add_lock(count, amount, lock_type, core::ptr::null(), 0) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::kernel::resource_op::{ResourceOpHooks, RESOURCE_OP_HOOKS, RESOURCE_OP_HOOKS_TEST_LOCK};
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ASN1_REFCOUNT, 0x1000).map(|p| p as usize)
    });

    struct Restore(ResourceOpHooks);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(self.0) };
        }
    }

    #[test]
    fn unsupported_items_do_not_read_value_or_auxiliary() {
        let mut item = [0u32; 5];
        item[4] = 1; // Invalid address: non-sequence must not dereference it.
        for kind in [0, 2, 3, 255] {
            item[0] = kind;
            assert_eq!(unsafe { asn1_do_ref(core::ptr::null(), -1, item.as_ptr()) }, 0);
        }
        item[0] = 1;
        item[4] = 0;
        assert_eq!(unsafe { asn1_do_ref(core::ptr::null(), 0, item.as_ptr()) }, 0);
    }

    #[test]
    fn initializes_adjusts_and_wraps_only_the_selected_count() {
        let _lock = RESOURCE_OP_HOOKS_TEST_LOCK.lock();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("crypto/asn1_refcount"));
            return;
        };
        let base = base as *mut u32;
        let saved = unsafe { core::ptr::addr_of!(RESOURCE_OP_HOOKS).read() };
        let _restore = Restore(saved);
        unsafe {
            core::ptr::addr_of_mut!(RESOURCE_OP_HOOKS).write(ResourceOpHooks {
                static_op: None, add_lock_callback: None, object_op: None, ..saved
            });
            core::ptr::write_bytes(base, 0, 0x1000 / 4);
            let item = base.add(8);
            let aux = base.add(16);
            let object = base.add(32);
            item.write(0x10001); // The kind is a byte, not the entire word.
            item.add(4).write(aux as usize as u32);
            aux.add(1).write(2); // Other flags alone do not enable counting.
            assert_eq!(asn1_do_ref(core::ptr::null(), 0, item), 0);
            aux.add(1).write(3);
            aux.add(2).write(8);
            aux.add(3).write(7);
            base.write(object as usize as u32);
            object.write(0xabcdef01);
            object.add(2).write(99);
            object.add(3).write(0x76543210);
            assert_eq!(asn1_do_ref(base, 0, item), 1);
            assert_eq!(object.add(2).read(), 1);
            assert_eq!(asn1_do_ref(base, 1, item), 2);
            assert_eq!(asn1_do_ref(base, -2, item), 0);
            assert_eq!(object.add(2).read(), 0);
            object.add(2).write(i32::MAX as u32);
            assert_eq!(asn1_do_ref(base, 1, item), i32::MIN);
            assert_eq!(object.add(2).read(), i32::MIN as u32);
            // Negative byte offset exercises ARM modulo-2^32 address addition.
            base.write(object.add(3) as usize as u32);
            aux.add(2).write((-4i32) as u32);
            assert_eq!(asn1_do_ref(base, 0, item), 1);
            assert_eq!(object.add(2).read(), 1);
            assert_eq!(object.read(), 0xabcdef01);
            assert_eq!(object.add(3).read(), 0x76543210);
        }
    }
}

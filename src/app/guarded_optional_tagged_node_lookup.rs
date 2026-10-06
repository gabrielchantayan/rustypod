//! guarded_optional_tagged_node_lookup — FUN_08168914 @ 0x08168914.
//! True extent [0x08168914,0x081689ac): 152 bytes, including the root-slot
//! literal at 0x081689a8. Whole-image A32 decoding verifies two incoming plain
//! BLs (0x08211520, 0x082c7d9c), six outgoing plain BLs, and no predicated BLs.
//!
//! Initialize an empty tagged record and construct a scoped global guard.
//! For a nonzero key pair, load application root+0x30, look up a node, construct
//! a temporary record with its pointer and receiver byte +0x44, and copy its
//! payload/flag. Destroy the temporary and finally the guard. Zero keys skip
//! all root/receiver reads but still construct and destroy the guard.
//!
//! Deliberate deviations: existing Rust initializer, lookup and destructor
//! ports replace retail calls. Raw guard construction at 0x08155b4c leaves
//! r1=0, explicitly passed here: the lookup uses node ID (0,key_low), while
//! key_high only controls the nonzero check (lookup ignores its fourth arg).
//! The registry's string-tail identification of the guard constructor conflicts
//! with raw PUSH/BL/stores/POP words; its verified role is retained as a stock
//! seam, not a new product identity. Host injection replaces root RAM and this
//! unported constructor. Return is void, not an incidental local guard pointer.

use crate::cxx::tagged_record::{TaggedRecord, tagged_record_init};
use crate::cxx::empty_destructor::empty_destructor;
use crate::util::scoped_global_guard_destroy::{ScopedGlobalGuard, scoped_global_guard_destroy};
use crate::ui::tdat_node_lookup::ui_tdat_node_lookup;
use core::mem::MaybeUninit;

type ConstructGuard = unsafe extern "C" fn(*mut ScopedGlobalGuard) -> *mut ScopedGlobalGuard;

/// # Safety
/// Result must be four-byte aligned and writable for twelve bytes. For nonzero
/// keys, receiver must be readable at +0x44 and the retail root/lookup structures
/// must be valid. Initial result stores precede any aliased receiver read.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn guarded_optional_tagged_node_lookup(
    result: *mut TaggedRecord, receiver: *const u8, key_low: u32, key_high: u32,
) {
    unsafe {
        tagged_record_init(result, 0, 0);
        let mut guard = MaybeUninit::<ScopedGlobalGuard>::uninit();
        #[cfg(target_os = "none")]
        let construct: ConstructGuard = core::mem::transmute(0x08155b4cusize);
        #[cfg(not(target_os = "none"))]
        let construct = HOST_DEPENDENCIES.expect("retail guard dependencies required on host").1;
        construct(guard.as_mut_ptr());
        if key_low != 0 || key_high != 0 {
            #[cfg(target_os = "none")]
            let owner = {
                let root = (0x089ca674 as *const *const u32).read();
                root.add(0x30 / 4).read() as usize as *const u8
            };
            #[cfg(not(target_os = "none"))]
            let owner = HOST_DEPENDENCIES.expect("retail root required on host").0;
            let payload = ui_tdat_node_lookup(owner, 0, key_low, key_high) as usize as u32;
            let flag = receiver.add(0x44).read();
            let mut temporary = MaybeUninit::<TaggedRecord>::uninit();
            let temporary = tagged_record_init(temporary.as_mut_ptr(), payload, flag as u32);
            core::ptr::addr_of_mut!((*result).payload).write((*temporary).payload);
            core::ptr::addr_of_mut!((*result).flag).write((*temporary).flag);
            empty_destructor(temporary.cast());
        }
        scoped_global_guard_destroy(guard.as_mut_ptr());
    }
}

#[cfg(not(target_os = "none"))]
static mut HOST_DEPENDENCIES: Option<(*const u8, ConstructGuard)> = None;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::tagged_record::TAGGED_RECORD_DESCRIPTOR;
    extern crate std;
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn construct(guard: *mut ScopedGlobalGuard) -> *mut ScopedGlobalGuard {
        unsafe { guard.cast::<u32>().write(0x08986aa0); guard.cast::<u32>().add(1).write(0); }
        guard
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { HOST_DEPENDENCIES = None; } }
    }

    #[test]
    fn zero_key_does_not_read_null_root_or_receiver() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _reset = Reset;
        unsafe { HOST_DEPENDENCIES = Some((core::ptr::null(), construct)); }
        let mut result = [0xa5a5a5a5u32; 3];
        unsafe { guarded_optional_tagged_node_lookup(result.as_mut_ptr().cast(), core::ptr::null(), 0, 0); }
        assert_eq!(result, [TAGGED_RECORD_DESCRIPTOR, 0, 0xa5a5a500]);
    }

    #[test]
    fn either_key_word_enables_flag_copy_even_when_real_lookup_returns_null() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _reset = Reset;
        // Large, aligned real owner: its lookup context at +0xf9c is NULL.
        let owner = [0usize; 0x1000 / core::mem::size_of::<usize>()];
        unsafe { HOST_DEPENDENCIES = Some((owner.as_ptr().cast(), construct)); }
        for (low, high, flag) in [(1, 0, 255), (0, 1, 128), (u32::MAX, u32::MAX, 1)] {
            let mut receiver = [0u8; 0x45];
            receiver[0x44] = flag;
            let mut result = [0xa5a5a5a5u32; 3];
            unsafe { guarded_optional_tagged_node_lookup(result.as_mut_ptr().cast(), receiver.as_ptr(), low, high); }
            assert_eq!(result, [TAGGED_RECORD_DESCRIPTOR, 0, 0xa5a5a500 | flag as u32]);
        }
    }

    #[test]
    fn initial_result_store_wins_over_aliased_receiver_flag() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _reset = Reset;
        let owner = [0usize; 0x1000 / core::mem::size_of::<usize>()];
        unsafe { HOST_DEPENDENCIES = Some((owner.as_ptr().cast(), construct)); }
        let mut storage = [0xeeeeeeeeu32; 20];
        unsafe { guarded_optional_tagged_node_lookup(storage.as_mut_ptr().add(15).cast(), storage.as_ptr().cast(), 1, 0); }
        assert_eq!(storage[15..19], [TAGGED_RECORD_DESCRIPTOR, 0, 0xeeeeee00, 0xeeeeeeee]);
    }
}

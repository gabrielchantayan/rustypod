//! six_bit_set_state_construct — original: `FUN_0816f508` @ `0x0816f508`.
//!
//! Load address: `0x0816f508`; true size: 180 bytes (`0x0816f508..0x0816f5bb`),
//! followed by the literal `0x08182e10` and then a separate destructor at
//! `0x0816f5c0`. Raw A32 decoding finds eight outbound plain `bl` instructions
//! (the allocator and bit-set constructor are each called three times), no
//! predicated `bl`, and three inbound plain `bl` calls at `0x08132ebc`,
//! `0x0813348c`, and `0x08133f88`; no predicated inbound `bl` calls.
//!
//! Constructs the six 12-byte state records at `+0x14`, initializes the
//! embedded condition variable at `+0x5c`, creates three empty bit sets from
//! the supplied capacities, clears the state word at `+0x10`, and clears each
//! record's halfword at `+0x1a`. Deliberate deviation: the anonymous target
//! object is addressed as bytes rather than a host-pointer-bearing Rust struct;
//! this preserves its fixed 32-bit target offsets on 64-bit host builds.

use crate::cxx::bit_set::{bit_set_construct, BitSet};
use crate::heap::veneers::operator_new;
use crate::kernel::condvar::{condvar_init, CondVar};
use crate::runtime::cpp_array_construct::cpp_array_construct;

pub const SIX_BIT_SET_STATE_SIZE: usize = 0x74;
const RECORDS_OFFSET: usize = 0x14;
const RECORD_SIZE: usize = 0x0c;
const RECORD_COUNT: usize = 6;
const RECORD_STATE_OFFSET: usize = 0x1a;
const CONDVAR_OFFSET: usize = 0x5c;
const FIRST_BIT_SET_OFFSET: usize = 0x04;
const BIT_SET_COUNT: usize = 3;
const BIT_SET_ELEMENT_CONSTRUCTOR: u32 = 0x0818_2e10;

#[inline(always)]
unsafe fn clear_record_states(state: *mut u8) {
    for index in 0..RECORD_COUNT {
        core::ptr::write_volatile(
            state.add(RECORDS_OFFSET + index * RECORD_SIZE + RECORD_STATE_OFFSET).cast::<u16>(),
            0,
        );
    }
}

/// Constructs the 0x74-byte state object in caller-provided allocated storage.
///
/// # Safety
///
/// The tag-2 allocator and the array/condition-variable hooks must provide the
/// same valid target-memory contracts as retailOS. Allocation failure is not
/// guarded, matching the original direct stores and constructor calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn six_bit_set_state_construct(
    storage: *mut u8,
    first_capacity: u32,
    second_capacity: u32,
    third_capacity: u32,
) -> *mut u8 {
    storage.write_volatile(0);
    cpp_array_construct(
        storage.add(RECORDS_OFFSET).cast(),
        BIT_SET_ELEMENT_CONSTRUCTOR,
        RECORD_SIZE as u32,
        RECORD_COUNT as u32,
    );
    condvar_init(storage.add(CONDVAR_OFFSET).cast::<CondVar>());
    for offset in [0x68, 0x6c, 0x70] {
        core::ptr::write_volatile(storage.add(offset).cast::<u32>(), 0);
    }

    let capacities = [first_capacity, second_capacity, third_capacity];
    for (index, capacity) in capacities.into_iter().enumerate() {
        let set_storage = operator_new(core::mem::size_of::<BitSet>()).cast::<BitSet>();
        let set = bit_set_construct(set_storage, capacity, 0);
        core::ptr::write_volatile(
            storage.add(FIRST_BIT_SET_OFFSET + index * core::mem::size_of::<u32>()).cast::<u32>(),
            set as usize as u32,
        );
    }

    clear_record_states(storage);
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_each_of_the_six_record_state_halfwords() {
        let mut state = [0xa5_u8; SIX_BIT_SET_STATE_SIZE];
        unsafe { clear_record_states(state.as_mut_ptr()) };

        for index in 0..RECORD_COUNT {
            let offset = RECORDS_OFFSET + index * RECORD_SIZE + RECORD_STATE_OFFSET;
            assert_eq!(&state[offset..offset + 2], &[0, 0]);
            assert_eq!(state[offset - 1], 0xa5);
            assert_eq!(state[offset + 2], 0xa5);
        }
        assert_eq!(state[0], 0xa5);
        assert_eq!(state[CONDVAR_OFFSET], 0xa5);
        assert_eq!(state[0x68], 0xa5);
    }
}

//! `vtable_state_construct` — original: `FUN_0817e898` @ `0x0817e898`
//! (**76-byte true extent**). Raw A32 establishes 72 instruction bytes
//! (`0x0817e898..0x0817e8df`), followed by the `0x08989484` vtable literal at
//! `0x0817e8e0`; the distinct next function starts at `0x0817e8e4`.
//! Independent decoding of every A32 branch-with-link in `osos.dec` finds
//! four inbound plain, unconditional `bl` calls (0x0819bb28, 0x081bb260,
//! 0x081bb670, and 0x081cb574), with no predicated `bl` calls.
//!
//! # Algorithm
//!
//! Installs its base vtable, copies five caller-supplied words (the middle two
//! from a two-word source), and clears the trailing six state words. It never
//! changes r0, so returns the caller-provided storage. Each direct caller
//! immediately replaces the installed base vtable with its derived vtable.
//!
//! # Deliberate deviations
//!
//! The base class identity is not established. `VtableState` names only the
//! verified layout and initialization behavior.

pub const VTABLE_STATE_VTABLE: u32 = 0x0898_9484;
pub const VTABLE_STATE_SIZE: usize = 0x30;

/// The two adjacent target words copied from the third constructor argument.
#[repr(C)]
pub struct VtableStateSource {
    pub first: u32,
    pub second: u32,
}

/// Target-layout state initialized by [`vtable_state_construct`].
#[repr(C)]
pub struct VtableState {
    pub vtable: u32,
    pub first_value: u32,
    pub source_first: u32,
    pub source_second: u32,
    pub third_value: u32,
    pub fourth_value: u32,
    pub trailing: [u32; 6],
}

const _: [u8; VTABLE_STATE_SIZE] = [0; core::mem::size_of::<VtableState>()];

/// Initializes base state in caller-provided storage and returns `storage`.
///
/// # Safety
///
/// `storage` and `source` must be valid, word-aligned pointers. `storage` must
/// reference at least [`VTABLE_STATE_SIZE`] writable bytes. The retail code
/// performs no NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_state_construct(
    storage: *mut VtableState,
    first_value: u32,
    source: *const VtableStateSource,
    third_value: u32,
    fourth_value: u32,
) -> *mut VtableState {
    core::ptr::addr_of_mut!((*storage).first_value).write_volatile(first_value);
    core::ptr::addr_of_mut!((*storage).vtable).write_volatile(VTABLE_STATE_VTABLE);
    core::ptr::addr_of_mut!((*storage).source_first).write_volatile((*source).first);
    core::ptr::addr_of_mut!((*storage).trailing)
        .cast::<u32>()
        .write_volatile(0);
    core::ptr::addr_of_mut!((*storage).source_second).write_volatile((*source).second);
    core::ptr::addr_of_mut!((*storage).third_value).write_volatile(third_value);
    core::ptr::addr_of_mut!((*storage).fourth_value).write_volatile(fourth_value);
    for index in 1..6 {
        core::ptr::addr_of_mut!((*storage).trailing)
            .cast::<u32>()
            .add(index)
            .write_volatile(0);
    }
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct GuardedState {
        before: u32,
        state: VtableState,
        after: u32,
    }

    #[test]
    fn installs_base_layout_and_clears_all_trailing_words() {
        let source = VtableStateSource { first: 0x1122_3344, second: 0x5566_7788 };
        let mut guarded: GuardedState = unsafe { core::mem::zeroed() };
        guarded.before = 0xa5a5_a5a5;
        guarded.after = 0x5a5a_5a5a;
        guarded.state = VtableState {
            vtable: u32::MAX,
            first_value: u32::MAX,
            source_first: u32::MAX,
            source_second: u32::MAX,
            third_value: u32::MAX,
            fourth_value: u32::MAX,
            trailing: [u32::MAX; 6],
        };

        let returned = unsafe {
            vtable_state_construct(
                core::ptr::addr_of_mut!(guarded.state),
                0x0102_0304,
                core::ptr::addr_of!(source),
                0x99aa_bbcc,
                0xddee_ff00,
            )
        };

        assert_eq!(returned, core::ptr::addr_of_mut!(guarded.state));
        assert_eq!(guarded.before, 0xa5a5_a5a5);
        assert_eq!(guarded.after, 0x5a5a_5a5a);
        assert_eq!(guarded.state.vtable, VTABLE_STATE_VTABLE);
        assert_eq!(guarded.state.first_value, 0x0102_0304);
        assert_eq!(guarded.state.source_first, source.first);
        assert_eq!(guarded.state.source_second, source.second);
        assert_eq!(guarded.state.third_value, 0x99aa_bbcc);
        assert_eq!(guarded.state.fourth_value, 0xddee_ff00);
        assert_eq!(guarded.state.trailing, [0; 6]);
    }

    #[test]
    fn source_aliasing_storage_observes_prior_stores() {
        let mut state: VtableState = unsafe { core::mem::zeroed() };
        state.vtable = 0x1111_2222;
        state.first_value = 0x3333_4444;

        unsafe {
            vtable_state_construct(
                core::ptr::addr_of_mut!(state),
                0x5555_6666,
                core::ptr::addr_of!(state).cast(),
                0x7777_8888,
                0x9999_aaaa,
            );
        }

        assert_eq!(state.source_first, VTABLE_STATE_VTABLE);
        assert_eq!(state.source_second, 0x5555_6666);
    }
}

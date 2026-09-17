//! `beeper_construct` — original: `FUN_08271598` @ 0x08271598 (84 bytes,
//! 0x08271598..0x082715eb). The literal pool starts at 0x082715ec and the
//! next real function starts at 0x082715f8. Raw A32 decoding finds **one
//! unconditional plain `bl`** (`0x082715d0 -> 0x08277304`) and no predicated
//! `bl` instructions. The image contains three incoming plain `bl` call sites
//! (0x081088b8, 0x08108b30, and 0x08108be4); no predicated incoming calls.
//!
//! # Algorithm
//!
//! Initializes the 0x38-byte Beeper state: installs vtable 0x089a5cfc, sets
//! its mode and timing defaults, constructs the embedded StringObject at
//! +0x20 from the literal `"Beeper"`, then clears/enables its trailing state
//! and records the caller's timing source.
//!
//! # Deliberate deviations
//!
//! On target this calls the ported `string_object_construct_from_cstr` directly,
//! preserving its returned-member-minus-0x20 pointer flow. Host `StringObject`
//! has native pointer-width fields, so the host path models its two target words
//! at +0x20/+0x24 instead; this keeps the enclosing target layout and does not
//! model the callee's heap allocation.

#[cfg(target_os = "none")]
use crate::cxx::string_object::{string_object_construct_from_cstr, StringObject};

pub const BEEPER_SIZE: usize = 0x38;
pub const BEEPER_VTABLE: u32 = 0x089a_5cfc;
pub const BEEPER_NAME: &[u8; 7] = b"Beeper\0";

/// Target-layout state initialized by [`beeper_construct`].
#[repr(C)]
pub struct Beeper {
    pub vtable: u32,
    pub mode: u32,
    pub opaque_08: u32,
    pub opaque_0c: u32,
    pub opaque_10: u32,
    pub interval: u32,
    pub next_deadline: u32,
    pub repeat_limit: u32,
    pub name: [u32; 2],
    pub opaque_28: u32,
    pub enabled: u8,
    pub enabled_tail: [u8; 3],
    pub opaque_30: u32,
    pub timing_source: u32,
}

const _: [u8; 0x20] = [0; core::mem::offset_of!(Beeper, name)];
const _: [u8; 0x28] = [0; core::mem::offset_of!(Beeper, opaque_28)];
const _: [u8; 0x2c] = [0; core::mem::offset_of!(Beeper, enabled)];
const _: [u8; 0x34] = [0; core::mem::offset_of!(Beeper, timing_source)];
const _: [u8; BEEPER_SIZE] = [0; core::mem::size_of::<Beeper>()];

#[cfg(target_os = "none")]
unsafe fn construct_name(storage: *mut Beeper) -> *mut Beeper {
    string_object_construct_from_cstr(storage.cast::<u8>().add(0x20).cast::<StringObject>(), BEEPER_NAME.as_ptr())
        .cast::<u8>()
        .sub(0x20)
        .cast()
}

#[cfg(not(target_os = "none"))]
unsafe fn construct_name(storage: *mut Beeper) -> *mut Beeper {
    (*storage).name = [0x089a_6044, 0];
    storage
}

/// Constructs Beeper state in caller-provided storage.
///
/// # Safety
/// `storage` must point to at least [`BEEPER_SIZE`] writable, word-aligned
/// bytes. The original performs no NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn beeper_construct(storage: *mut Beeper, timing_source: u32) -> *mut Beeper {
    core::ptr::addr_of_mut!((*storage).vtable).write_volatile(BEEPER_VTABLE);
    core::ptr::addr_of_mut!((*storage).mode).write_volatile(3);
    core::ptr::addr_of_mut!((*storage).opaque_08).write_volatile(0);
    core::ptr::addr_of_mut!((*storage).interval).write_volatile(8);
    core::ptr::addr_of_mut!((*storage).next_deadline).write_volatile(0);
    core::ptr::addr_of_mut!((*storage).repeat_limit).write_volatile(u32::MAX);

    let beeper = construct_name(storage);
    core::ptr::addr_of_mut!((*beeper).opaque_28).write_volatile(0);
    core::ptr::addr_of_mut!((*beeper).enabled).write_volatile(1);
    core::ptr::addr_of_mut!((*beeper).timing_source).write_volatile(timing_source);
    beeper
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct GuardedBeeper {
        before: u32,
        beeper: Beeper,
        after: u32,
    }

    #[test]
    fn initializes_target_words_and_preserves_unwritten_words() {
        let mut storage: GuardedBeeper = unsafe { core::mem::zeroed() };
        storage.before = 0xa5a5_a5a5;
        storage.after = 0x5a5a_5a5a;
        storage.beeper.opaque_0c = 0x1111_2222;
        storage.beeper.opaque_10 = 0x3333_4444;
        storage.beeper.enabled_tail = [0x55, 0x66, 0x77];
        storage.beeper.opaque_30 = 0x8888_9999;

        let returned = unsafe { beeper_construct(core::ptr::addr_of_mut!(storage.beeper), 0xdead_beef) };

        assert_eq!(returned, core::ptr::addr_of_mut!(storage.beeper));
        assert_eq!(storage.before, 0xa5a5_a5a5);
        assert_eq!(storage.after, 0x5a5a_5a5a);
        assert_eq!(storage.beeper.vtable, BEEPER_VTABLE);
        assert_eq!(storage.beeper.mode, 3);
        assert_eq!(storage.beeper.opaque_08, 0);
        assert_eq!(storage.beeper.opaque_0c, 0x1111_2222);
        assert_eq!(storage.beeper.opaque_10, 0x3333_4444);
        assert_eq!(storage.beeper.interval, 8);
        assert_eq!(storage.beeper.next_deadline, 0);
        assert_eq!(storage.beeper.repeat_limit, u32::MAX);
        assert_eq!(storage.beeper.name, [0x089a_6044, 0]);
        assert_eq!(storage.beeper.opaque_28, 0);
        assert_eq!(storage.beeper.enabled, 1);
        assert_eq!(storage.beeper.enabled_tail, [0x55, 0x66, 0x77]);
        assert_eq!(storage.beeper.opaque_30, 0x8888_9999);
        assert_eq!(storage.beeper.timing_source, 0xdead_beef);
    }
}

//! Accessor for an unidentified UI object's state word.

/// object_state_word — original: `FUN_08055e80` @ `0x08055e80` (12 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055e80_FUN_08055e80.c`.
/// The ARM leaf loads and returns the little-endian 32-bit state word at
/// offset `0xe38` in an otherwise unidentified UI object. It performs no
/// null or alignment checks, matching the original `ldr` ABI.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_state_word(object: *const u8) -> u32 {
    (object.add(0xe38) as *const u32).read()
}

/// object_state_kind — original: `FUN_08055e00` @ `0x08055e00` (128 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055e00_FUN_08055e00.c`;
/// assembly: `decomp/osos.asm` @ `0x08055e00..0x08055e7c`.
///
/// Loads the 32-bit state word at object offset `0xe38` (the same word
/// [`object_state_word`] exposes) and maps it through a ten-entry branch
/// table (`addls pc,pc,r0,lsl #2` after `cmp r0,#9`) to a small kind code:
/// state 0 -> 9, 2 -> 0x18, 3 -> 6, 4 -> 5, 5 -> 1, 6 -> 0x24, 7 -> 0x28,
/// 9 -> 0x2a. States 1 and 8, plus any state word above 9 (the `addls`
/// guard makes the comparison unsigned), fall through to the default code
/// 7. The meaning of the individual kind codes is not recovered; the nine
/// stock call sites forward the code to other UI helpers. Like the original
/// `ldr` at entry, there is no null or alignment guard on `object`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_state_kind(object: *const u8) -> u32 {
    match object_state_word(object) {
        0 => 0x09,
        2 => 0x18,
        3 => 0x06,
        4 => 0x05,
        5 => 0x01,
        6 => 0x24,
        7 => 0x28,
        9 => 0x2a,
        _ => 0x07,
    }
}
/// Byte offset of the nested object pointer (`ldr r0, [r0, #0xf00]`).
const NESTED_OBJECT_POINTER_OFFSET: usize = 0xf00;

/// Byte offset of the flag inside the nested object (`ldrb r0, [r0, #0xb88]`).
const NESTED_OBJECT_FLAG_OFFSET: usize = 0xb88;

/// Byte offset of the property byte inside the nested object
/// (`ldrb r0, [r0, #0xb51]`).
const NESTED_OBJECT_PROPERTY_OFFSET: usize = 0xb51;

/// Byte offset of the attribute byte inside the nested object
/// (`ldrb r0, [r0, #0xb66]`).
const NESTED_OBJECT_ATTRIBUTE_OFFSET: usize = 0xb66;

/// object_nested_flag — original: `FUN_08055f90` @ `0x08055f90` (12 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055f90_FUN_08055f90.c`;
/// raw ARM: `ldr r0, [r0, #0xf00]; ldrb r0, [r0, #0xb88]; bx lr`.
/// The leaf follows the pointer at `object + 0xf00`, then loads and returns
/// that nested object's byte at `+0xb88`. `ldrb` zero-extends the returned
/// byte in `r0`; the port exposes that unsigned ABI result as `u8`. Neither
/// pointer is null-checked, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_nested_flag(object: *const u8) -> u8 {
    let nested_object = (object.add(NESTED_OBJECT_POINTER_OFFSET) as *const *const u8).read();
    nested_object.add(NESTED_OBJECT_FLAG_OFFSET).read()
}

/// object_nested_property — original: `FUN_08055f9c` @ `0x08055f9c` (12
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055f9c_FUN_08055f9c.c`;
/// raw ARM: `ldr r0, [r0, #0xf00]; ldrb r0, [r0, #0xb51]; bx lr`.
/// The leaf follows the pointer at `object + 0xf00` (the same nested object
/// [`object_nested_flag`] dereferences), then loads and returns that nested
/// object's byte at `+0xb51`. `ldrb` zero-extends the returned byte in `r0`;
/// the port exposes that unsigned ABI result as `u8`. Neither pointer is
/// null-checked, matching the original. Both stock call sites (in the
/// change-notification routine at 0x081732b0/0x081732c4) cache the byte and
/// fire a virtual callback when it changes, so it behaves as a polled
/// property of the nested object; the property's concrete meaning remains
/// unidentified. The adjacent 0x08055fa8 is the same shape with offset
/// `0xb66` and is a separate function, not a duplicate.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_nested_property(object: *const u8) -> u8 {
    let nested_object = (object.add(NESTED_OBJECT_POINTER_OFFSET) as *const *const u8).read();
    nested_object.add(NESTED_OBJECT_PROPERTY_OFFSET).read()
}

/// object_nested_attribute — original: `FUN_08055fa8` @ `0x08055fa8` (12
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055fa8_FUN_08055fa8.c`;
/// raw ARM: `ldr r0, [r0, #0xf00]; ldrb r0, [r0, #0xb66]; bx lr`.
/// The leaf follows the pointer at `object + 0xf00` (the same nested object
/// [`object_nested_flag`] and [`object_nested_property`] dereference), then
/// loads and returns that nested object's byte at `+0xb66`. `ldrb`
/// zero-extends the returned byte in `r0`; the port exposes that unsigned
/// ABI result as `u8`. Neither pointer is null-checked, matching the
/// original. Both stock call sites (at 0x081a3890 and 0x081a4d60) store the
/// byte into caller state at `+0xa1` — the second then gates a virtual
/// dispatch on the adjacent byte at `+0xa0` — so it behaves as a cached
/// attribute of the nested object; the attribute's concrete meaning remains
/// unidentified. This is a distinct accessor from the adjacent
/// [`object_nested_property`] @ 0x08055f9c, which reads offset `0xb51`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_nested_attribute(object: *const u8) -> u8 {
    let nested_object = (object.add(NESTED_OBJECT_POINTER_OFFSET) as *const *const u8).read();
    nested_object.add(NESTED_OBJECT_ATTRIBUTE_OFFSET).read()
}


/// The UI sequence identifier state (original global @ `0x089c_fcc4`).
///
/// The firmware reaches this runtime-initialized word through the literal at
/// `0x0805_5ecc`; this static models that target-side state.
pub static mut SEQUENCE_ID: u32 = 0;

/// sequence_id_next — original: `FUN_08055eb8` @ `0x08055eb8` (16 bytes).
///
/// Sources: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055eb8_FUN_08055eb8.c`
/// and `decomp/osos.asm` @ `0x08055eb8..0x08055ec8`. The decompilation
/// incorrectly declares `void`; the ARM leaf leaves the loaded word in `r0`.
/// It loads the sequence word at `0x089c_fcc4` through its `0x0805_5ecc`
/// literal, stores that word plus one with wrapping 32-bit arithmetic, and
/// returns the pre-increment value. The runtime global is modeled by
/// [`SEQUENCE_ID`] rather than its fixed device address.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sequence_id_next() -> u32 {
    let state = core::ptr::addr_of_mut!(SEQUENCE_ID);
    let sequence_id = core::ptr::read_volatile(state);
    core::ptr::write_volatile(state, sequence_id.wrapping_add(1));
    sequence_id
}

/// The three words inspected by [`indexed_object_offset`], followed by the
/// storage word consumed by its unported base-address callee.
///
/// Call sites at 0x08066bb8, 0x080e2d70, and 0x080e2dc8 pass this header and
/// use a one-based index to address fixed-size records. The callee at
/// 0x080aa828 verifies the same tag and reads `storage` at byte offset 24.
#[repr(C)]
pub struct IndexedObject {
    /// Fixed object-format tag: the literal at 0x08055f20 is `0x6172_6179`.
    pub type_tag: u32,
    /// Byte stride of one stored record.
    pub element_size: u32,
    /// Number of addressable records.
    pub element_count: u32,
    /// Header words not inspected by this helper.
    pub reserved: [u32; 3],
    /// Storage pointer read by the unported 0x080aa828 base-address helper.
    pub storage: *mut u8,
}

/// Object tag loaded from the literal pool at 0x08055f20.
pub const INDEXED_OBJECT_TAG: u32 = 0x6172_6179;

type IndexedObjectStorageBase = unsafe extern "C" fn(*const IndexedObject) -> *mut u8;

/// Calls the stock object-storage-base helper, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x080aa828. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address.
unsafe extern "C" fn firmware_indexed_object_storage_base(
    object: *const IndexedObject,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let storage_base: IndexedObjectStorageBase =
            core::mem::transmute(0x080a_a828usize);
        storage_base(object)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = object;
        core::ptr::null_mut()
    }
}

/// Narrow boundary for the unported 0x080aa828 dependency.
static mut INDEXED_OBJECT_STORAGE_BASE: IndexedObjectStorageBase =
    firmware_indexed_object_storage_base;

#[inline(always)]
unsafe fn indexed_object_storage_base() -> IndexedObjectStorageBase {
    core::ptr::read_volatile(core::ptr::addr_of!(INDEXED_OBJECT_STORAGE_BASE))
}

/// indexed_object_offset — original: `FUN_08055ed0` @ `0x08055ed0` (80
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055ed0_FUN_08055ed0.c`;
/// assembly: `decomp/osos.asm` @ `0x08055ed0..0x08055f1c`.
///
/// Addresses one-based fixed-size records in an [`IndexedObject`]. It first
/// requires the literal [`INDEXED_OBJECT_TAG`], a nonzero index, and
/// `index <= element_count`; only then does it call retailOS helper
/// 0x080aa828 for the storage base and add `element_size * (index - 1)`.
///
/// # Safety
///
/// `object` must be readable as an aligned [`IndexedObject`]. Like the ARM
/// `ldr` at entry, this function has no null or alignment guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_object_offset(
    object: *const IndexedObject,
    index: u32,
) -> *mut u8 {
    if (*object).type_tag != INDEXED_OBJECT_TAG
        || index == 0
        || index > (*object).element_count
    {
        return core::ptr::null_mut();
    }

    let storage_base = indexed_object_storage_base()(object);
    storage_base.wrapping_add(
        (*object)
            .element_size
            .wrapping_mul(index.wrapping_sub(1)) as usize,
    )
}

/// Sampled-clock interface index the original passes to 0x0809b60c
/// (`mov r0,#0x0` before the `bl`).
const TIMESTAMP_INTERFACE: u32 = 0;

/// Fixed-point scale applied to the raw sample: a 64-bit left shift by 10
/// (`mov r1,r1,lsl #0xa; orr r1,r1,r0,lsr #0x16; mov r0,r0,lsl #0xa`).
const TIMESTAMP_SCALE_SHIFT: u32 = 10;

type ClockSample = unsafe extern "C" fn(u32) -> i64;

/// Calls the stock sampled-clock getter, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x0809b60c. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. The original constructs a temporary stack object
/// around interface `interface` (0x08206e40), reads its current sample via
/// 0x08296f18, destroys the object (0x08206e6c), and returns the sample
/// zero-extended to 64 bits in r0:r1.
unsafe extern "C" fn firmware_clock_sample(interface: u32) -> i64 {
    #[cfg(target_os = "none")]
    {
        let clock_sample: ClockSample = core::mem::transmute(0x0809_b60cusize);
        clock_sample(interface)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = interface;
        0
    }
}

/// Narrow boundary for the unported 0x0809b60c dependency.
static mut CLOCK_SAMPLE: ClockSample = firmware_clock_sample;

#[inline(always)]
unsafe fn clock_sample_fn() -> ClockSample {
    core::ptr::read_volatile(core::ptr::addr_of!(CLOCK_SAMPLE))
}

/// scaled_timestamp_now — original: `FUN_08055fb4` @ `0x08055fb4` (28
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055fb4_FUN_08055fb4.c`;
/// assembly: `decomp/osos.asm` @ `0x08055fb4..0x08055fcc`.
///
/// Calls retailOS sampled-clock getter 0x0809b60c with interface index
/// [`TIMESTAMP_INTERFACE`] and returns its 64-bit sample shifted left by
/// [`TIMESTAMP_SCALE_SHIFT`] bits in r0:r1 — a fixed-point timestamp 2^10
/// times finer than the raw getter's unit (the concrete unit is not
/// recovered). All three stock call sites (0x08141640, 0x081417a8,
/// 0x081eb42c) subtract a lazily snapshotted baseline from the result:
/// 0x08055ff8 returns the doubleword at global 0x089c_a5e0 + 0x20, first
/// populated by 0x08055fd0, which stores the identically scaled sample of
/// sibling getter 0x08090b88; the callers then convert the 64-bit delta to
/// `double`, so the function behaves as the "now" half of an elapsed-time
/// measurement. The original's `push {r4,lr}` never uses r4 — an ADS frame
/// artifact not reproduced here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scaled_timestamp_now() -> i64 {
    clock_sample_fn()(TIMESTAMP_INTERFACE) << TIMESTAMP_SCALE_SHIFT
}

/// The elapsed-time baseline slot at global 0x089c_a5e0 + 0x20.
///
/// The firmware reaches this doubleword through the literals at
/// `0x0805_5ff4` (0x08055fd0's `strd` store) and `0x0805_6024`
/// (0x08055ff8's lazy `ldrd` load), both holding 0x089c_a5e0; this static
/// models that target-side state. To the lazy getter 0x08055ff8, a zero
/// doubleword means "not yet snapshotted".
pub static mut TIMESTAMP_BASELINE: i64 = 0;

/// Calls the stock baseline-clock getter, which remains in retailOS.
///
/// This is deliberately a boundary rather than a port of 0x08090b88. Host
/// tests replace the one function pointer below; ARM builds call its fixed
/// firmware load address. Like its sibling 0x0809b60c (see
/// [`firmware_clock_sample`]), the original constructs a temporary stack
/// object around interface `interface` (0x08206e40) and destroys it
/// (0x08206e6c), but reads through the sibling accessor 0x08296ea4 instead
/// of 0x08296f18 and returns that 32-bit result zero-extended to 64 bits
/// in r0:r1 (`mov r1,r5` with r5 zeroed at 0x08090b9c).
unsafe extern "C" fn firmware_baseline_clock_sample(interface: u32) -> i64 {
    #[cfg(target_os = "none")]
    {
        let clock_sample: ClockSample = core::mem::transmute(0x0809_0b88usize);
        clock_sample(interface)
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = interface;
        0
    }
}

/// Narrow boundary for the unported 0x08090b88 dependency.
static mut BASELINE_CLOCK_SAMPLE: ClockSample = firmware_baseline_clock_sample;

#[inline(always)]
unsafe fn baseline_clock_sample_fn() -> ClockSample {
    core::ptr::read_volatile(core::ptr::addr_of!(BASELINE_CLOCK_SAMPLE))
}

/// snapshot_timestamp_baseline — original: `FUN_08055fd0` @ `0x08055fd0`
/// (36 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055fd0_FUN_08055fd0.c`;
/// assembly: `decomp/osos.asm` @ `0x08055fd0..0x08055ff0`.
///
/// Calls retailOS baseline-clock getter 0x08090b88 with interface index
/// [`TIMESTAMP_INTERFACE`], shifts its 64-bit sample left by
/// [`TIMESTAMP_SCALE_SHIFT`] bits (the same fixed-point scale
/// [`scaled_timestamp_now`] applies to sibling getter 0x0809b60c), and
/// stores the result as the doubleword at global 0x089c_a5e0 + 0x20
/// (`strd r0,r1,[r2,#0x20]`, modeled by [`TIMESTAMP_BASELINE`]). This is
/// the "snapshot" half of the firmware's elapsed-time measurement: the
/// lazy getter 0x08055ff8 calls it to populate a zero baseline, and all
/// three [`scaled_timestamp_now`] call sites subtract that baseline from
/// the current sample. Ghidra declares the original `void`, but it leaves
/// the scaled sample in r0:r1 and both non-trivial call sites rely on the
/// residue — 0x08055ff8 re-stores r0:r1 right after its `bl`, and
/// 0x081eb420 moves them into r6/r8 as the subtrahend for the following
/// `scaled_timestamp_now` delta — so the port returns the stored value.
/// The original's `push {r4,lr}` never uses r4 — an ADS frame artifact not
/// reproduced here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn snapshot_timestamp_baseline() -> i64 {
    let scaled_sample =
        baseline_clock_sample_fn()(TIMESTAMP_INTERFACE) << TIMESTAMP_SCALE_SHIFT;
    core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write_volatile(scaled_sample);
    scaled_sample
}

/// timestamp_baseline — original: `FUN_08055ff8` @ `0x08055ff8` (44
/// bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/003/08055ff8_FUN_08055ff8.c`;
/// assembly: `decomp/osos.asm` @ `0x08055ff8..0x08056020`.
///
/// Lazily initializes and returns the elapsed-time baseline doubleword at
/// global 0x089c_a5e0 + 0x20 (modeled by [`TIMESTAMP_BASELINE`]). It loads
/// the slot (`ldrd r0,r1,[r4,#0x20]`), treats a zero doubleword as "not
/// yet snapshotted" (`cmp r1,#0; cmpeq r0,r2`), and only then calls
/// [`snapshot_timestamp_baseline`] (0x08055fd0), storing its r0:r1 result
/// back into the slot (`strd r0,r1,[r4,#0x20]`) before returning it
/// (`ldrd` again). A nonzero slot is returned untouched, so the baseline
/// is sampled exactly once over the device's uptime. All three stock call
/// sites (0x0814164c, 0x081417b4, 0x081eb418) subtract the result from a
/// following [`scaled_timestamp_now`] sample and convert the 64-bit delta
/// to `double`, so this is the "zero point" half of the firmware's
/// elapsed-time measurement. The original's `push {r4,lr}` holds the
/// global pointer in r4 across the call — a register-allocation detail,
/// not observable state — and is not reproduced here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timestamp_baseline() -> i64 {
    if core::ptr::addr_of!(TIMESTAMP_BASELINE).read_volatile() == 0 {
        let scaled_sample = snapshot_timestamp_baseline();
        core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write_volatile(scaled_sample);
    }
    core::ptr::addr_of!(TIMESTAMP_BASELINE).read_volatile()
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::{Mutex, MutexGuard};

    static SEQUENCE_ID_LOCK: Mutex<()> = Mutex::new(());
    static INDEXED_OBJECT_STORAGE_BASE_LOCK: Mutex<()> = Mutex::new(());
    static CLOCK_SAMPLE_LOCK: Mutex<()> = Mutex::new(());
    static BASELINE_CLOCK_SAMPLE_LOCK: Mutex<()> = Mutex::new(());
    static mut CLOCK_SAMPLE_CALLS: u32 = 0;
    static mut CLOCK_SAMPLE_INTERFACE: u32 = u32::MAX;
    static mut MOCK_SAMPLE: i64 = 0;
    static mut BASELINE_SAMPLE_CALLS: u32 = 0;
    static mut BASELINE_SAMPLE_INTERFACE: u32 = u32::MAX;
    static mut MOCK_BASELINE_SAMPLE: i64 = 0;

    unsafe extern "C" fn recording_baseline_clock_sample(interface: u32) -> i64 {
        BASELINE_SAMPLE_CALLS += 1;
        BASELINE_SAMPLE_INTERFACE = interface;
        MOCK_BASELINE_SAMPLE
    }

    /// Restores the stock-call boundary before another test uses it.
    struct BaselineClockSampleReset;

    impl Drop for BaselineClockSampleReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BASELINE_CLOCK_SAMPLE)
                    .write(firmware_baseline_clock_sample);
                core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(0);
            }
        }
    }

    fn install_recording_baseline_clock_sample(sample: i64) -> MutexGuard<'static, ()> {
        let guard = BASELINE_CLOCK_SAMPLE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            BASELINE_SAMPLE_CALLS = 0;
            BASELINE_SAMPLE_INTERFACE = u32::MAX;
            MOCK_BASELINE_SAMPLE = sample;
            core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(i64::MIN);
            core::ptr::addr_of_mut!(BASELINE_CLOCK_SAMPLE)
                .write(recording_baseline_clock_sample);
        }
        guard
    }

    unsafe extern "C" fn recording_clock_sample(interface: u32) -> i64 {
        CLOCK_SAMPLE_CALLS += 1;
        CLOCK_SAMPLE_INTERFACE = interface;
        MOCK_SAMPLE
    }

    /// Restores the stock-call boundary before another test uses it.
    struct ClockSampleReset;

    impl Drop for ClockSampleReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CLOCK_SAMPLE).write(firmware_clock_sample);
            }
        }
    }

    fn install_recording_clock_sample(sample: i64) -> MutexGuard<'static, ()> {
        let guard = CLOCK_SAMPLE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CLOCK_SAMPLE_CALLS = 0;
            CLOCK_SAMPLE_INTERFACE = u32::MAX;
            MOCK_SAMPLE = sample;
            core::ptr::addr_of_mut!(CLOCK_SAMPLE).write(recording_clock_sample);
        }
        guard
    }
    static mut STORAGE_BASE_CALLS: u32 = 0;
    static mut STORAGE_BASE_OBJECT: usize = 0;
    static mut MOCK_STORAGE_BASE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_storage_base(object: *const IndexedObject) -> *mut u8 {
        STORAGE_BASE_CALLS += 1;
        STORAGE_BASE_OBJECT = object as usize;
        MOCK_STORAGE_BASE
    }

    /// Restores the stock-call boundary before another test uses it.
    struct StorageBaseReset;

    impl Drop for StorageBaseReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(INDEXED_OBJECT_STORAGE_BASE)
                    .write(firmware_indexed_object_storage_base);
            }
        }
    }

    fn install_recording_storage_base(storage_base: *mut u8) -> MutexGuard<'static, ()> {
        let guard = INDEXED_OBJECT_STORAGE_BASE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            STORAGE_BASE_CALLS = 0;
            STORAGE_BASE_OBJECT = 0;
            MOCK_STORAGE_BASE = storage_base;
            core::ptr::addr_of_mut!(INDEXED_OBJECT_STORAGE_BASE).write(recording_storage_base);
        }
        guard
    }

    fn indexed_object(
        type_tag: u32,
        element_size: u32,
        element_count: u32,
    ) -> IndexedObject {
        IndexedObject {
            type_tag,
            element_size,
            element_count,
            reserved: [0; 3],
            storage: core::ptr::null_mut(),
        }
    }

    fn seed_sequence_id(value: u32) {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SEQUENCE_ID), value);
        }
    }

    fn sequence_id() -> u32 {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SEQUENCE_ID)) }
    }

    #[test]
    fn returns_the_word_at_offset_e38() {
        let mut object = [0u8; 0xe3c];
        object[0xe38..0xe3c].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x89ab_cdef);
    }

    #[test]
    fn maps_every_jump_table_state_to_its_kind_code() {
        let mut object = [0u8; 0xe3c];
        let expected = [
            (0u32, 0x09u32),
            (1, 0x07),
            (2, 0x18),
            (3, 0x06),
            (4, 0x05),
            (5, 0x01),
            (6, 0x24),
            (7, 0x28),
            (8, 0x07),
            (9, 0x2a),
        ];

        for (state, kind) in expected {
            object[0xe38..0xe3c].copy_from_slice(&state.to_le_bytes());
            assert_eq!(unsafe { object_state_kind(object.as_ptr()) }, kind);
        }
    }

    #[test]
    fn out_of_range_states_fall_through_to_the_default_kind() {
        let mut object = [0u8; 0xe3c];

        for state in [10u32, 11, 0xffff, 0x8000_0000, u32::MAX] {
            object[0xe38..0xe3c].copy_from_slice(&state.to_le_bytes());
            assert_eq!(unsafe { object_state_kind(object.as_ptr()) }, 0x07);
        }
    }

    #[test]
    fn ignores_adjacent_object_bytes() {
        let mut object = [0xa5u8; 0xe40];
        object[0xe34..0xe38].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        object[0xe38..0xe3c].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        object[0xe3c..0xe40].copy_from_slice(&0x99aa_bbccu32.to_le_bytes());

        assert_eq!(unsafe { object_state_word(object.as_ptr()) }, 0x5566_7788);
    }

    #[test]
    fn returns_then_advances_the_sequence_state() {
        let _guard = SEQUENCE_ID_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        for initial in [0, 1, 0x2468_ace0, 0xffff_fffe] {
            seed_sequence_id(initial);
            assert_eq!(unsafe { sequence_id_next() }, initial);
            assert_eq!(sequence_id(), initial.wrapping_add(1));
        }
    }

    #[test]
    fn wraps_after_returning_the_maximum_sequence_id() {
        let _guard = SEQUENCE_ID_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        seed_sequence_id(u32::MAX);
        assert_eq!(unsafe { sequence_id_next() }, u32::MAX);
        assert_eq!(sequence_id(), 0);
        assert_eq!(unsafe { sequence_id_next() }, 0);
        assert_eq!(sequence_id(), 1);
    }
    #[test]
    fn wrong_type_tag_returns_null_without_querying_storage() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG ^ 1, 4, 1);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 1) },
            core::ptr::null_mut()
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 0);
    }

    #[test]
    fn zero_index_returns_null_without_querying_storage() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG, 4, 1);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 0) },
            core::ptr::null_mut()
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 0);
    }

    #[test]
    fn index_above_count_returns_null_without_querying_storage() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG, 4, 2);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 3) },
            core::ptr::null_mut()
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 0);
    }

    #[test]
    fn valid_one_based_indices_call_storage_base_and_scale_by_stride() {
        let mut storage = [0u8; 32];
        let _guard = install_recording_storage_base(storage.as_mut_ptr());
        let _reset = StorageBaseReset;
        let object = indexed_object(INDEXED_OBJECT_TAG, 12, 3);

        assert_eq!(
            unsafe { indexed_object_offset(&object, 1) },
            storage.as_mut_ptr(),
            "the first one-based record begins at the base"
        );
        assert_eq!(
            unsafe { indexed_object_offset(&object, 3) },
            unsafe { storage.as_mut_ptr().add(24) },
            "the upper inclusive index uses stride * (index - 1)"
        );
        assert_eq!(unsafe { STORAGE_BASE_CALLS }, 2);
        assert_eq!(unsafe { STORAGE_BASE_OBJECT }, &object as *const IndexedObject as usize);
    }
    #[test]
    fn follows_the_object_pointer_to_the_nested_flag() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_FLAG_OFFSET + 2]);

        let mut outer = OuterObject([0xa5; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0xa5; NESTED_OBJECT_FLAG_OFFSET + 2]);
        nested.0[NESTED_OBJECT_FLAG_OFFSET - 1] = 0x11;
        nested.0[NESTED_OBJECT_FLAG_OFFSET] = 0x5a;
        nested.0[NESTED_OBJECT_FLAG_OFFSET + 1] = 0xe2;

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            assert_eq!(object_nested_flag(outer.0.as_ptr()), 0x5a);
        }
    }

    #[test]
    fn returns_an_unsigned_byte() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_FLAG_OFFSET + 1]);

        let mut outer = OuterObject([0; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0; NESTED_OBJECT_FLAG_OFFSET + 1]);

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            for byte in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                nested.0[NESTED_OBJECT_FLAG_OFFSET] = byte;
                assert_eq!(
                    u32::from(object_nested_flag(outer.0.as_ptr())),
                    u32::from(byte),
                    "the ldrb result must be zero-extended for {byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn follows_the_object_pointer_to_the_nested_property() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_PROPERTY_OFFSET + 2]);

        let mut outer = OuterObject([0xa5; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0xa5; NESTED_OBJECT_PROPERTY_OFFSET + 2]);
        nested.0[NESTED_OBJECT_PROPERTY_OFFSET - 1] = 0x11;
        nested.0[NESTED_OBJECT_PROPERTY_OFFSET] = 0x3c;
        nested.0[NESTED_OBJECT_PROPERTY_OFFSET + 1] = 0xe2;

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            assert_eq!(object_nested_property(outer.0.as_ptr()), 0x3c);
        }
    }

    #[test]
    fn nested_property_is_an_unsigned_byte() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_PROPERTY_OFFSET + 1]);

        let mut outer = OuterObject([0; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0; NESTED_OBJECT_PROPERTY_OFFSET + 1]);

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            for byte in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                nested.0[NESTED_OBJECT_PROPERTY_OFFSET] = byte;
                assert_eq!(
                    u32::from(object_nested_property(outer.0.as_ptr())),
                    u32::from(byte),
                    "the ldrb result must be zero-extended for {byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn follows_the_object_pointer_to_the_nested_attribute() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_ATTRIBUTE_OFFSET + 2]);

        let mut outer = OuterObject([0xa5; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0xa5; NESTED_OBJECT_ATTRIBUTE_OFFSET + 2]);
        nested.0[NESTED_OBJECT_ATTRIBUTE_OFFSET - 1] = 0x11;
        nested.0[NESTED_OBJECT_ATTRIBUTE_OFFSET] = 0x3c;
        nested.0[NESTED_OBJECT_ATTRIBUTE_OFFSET + 1] = 0xe2;

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            assert_eq!(object_nested_attribute(outer.0.as_ptr()), 0x3c);
        }
    }

    #[test]
    fn nested_attribute_is_an_unsigned_byte() {
        #[repr(align(8))]
        struct OuterObject(
            [u8; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()],
        );
        #[repr(align(8))]
        struct NestedObject([u8; NESTED_OBJECT_ATTRIBUTE_OFFSET + 1]);

        let mut outer = OuterObject([0; NESTED_OBJECT_POINTER_OFFSET + core::mem::size_of::<*const u8>()]);
        let mut nested = NestedObject([0; NESTED_OBJECT_ATTRIBUTE_OFFSET + 1]);

        unsafe {
            (outer.0.as_mut_ptr().add(NESTED_OBJECT_POINTER_OFFSET) as *mut *const u8)
                .write(nested.0.as_ptr());
            for byte in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                nested.0[NESTED_OBJECT_ATTRIBUTE_OFFSET] = byte;
                assert_eq!(
                    u32::from(object_nested_attribute(outer.0.as_ptr())),
                    u32::from(byte),
                    "the ldrb result must be zero-extended for {byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn queries_interface_zero_and_scales_the_sample_by_two_to_the_tenth() {
        let _guard = install_recording_clock_sample(0x0012_3456_789a_bcde);
        let _reset = ClockSampleReset;

        assert_eq!(
            unsafe { scaled_timestamp_now() },
            0x0012_3456_789a_bcdei64 << 10
        );
        assert_eq!(unsafe { CLOCK_SAMPLE_CALLS }, 1);
        assert_eq!(
            unsafe { CLOCK_SAMPLE_INTERFACE },
            0,
            "the original passes interface index 0 (`mov r0,#0x0`)"
        );
    }

    #[test]
    fn scale_shift_carries_across_the_word_boundary() {
        let _guard = install_recording_clock_sample(0x003f_ffff_ffff_ffff);
        let _reset = ClockSampleReset;

        assert_eq!(
            unsafe { scaled_timestamp_now() },
            0x003f_ffff_ffff_ffffi64 << 10,
            "the top ten bits of r0 must shift into r1 (`orr r1,r1,r0,lsr #0x16`)"
        );
    }

    #[test]
    fn scale_shift_drops_bits_above_sixty_four() {
        let _guard = install_recording_clock_sample(-1);
        let _reset = ClockSampleReset;

        assert_eq!(unsafe { scaled_timestamp_now() }, -1i64 << 10);
    }

    #[test]
    fn baseline_snapshot_stores_the_scaled_sample_and_returns_it() {
        let _guard = install_recording_baseline_clock_sample(0x0012_3456_789a_bcde);
        let _reset = BaselineClockSampleReset;

        let returned = unsafe { snapshot_timestamp_baseline() };

        assert_eq!(
            returned,
            0x0012_3456_789a_bcdei64 << 10,
            "call sites 0x08055ff8 and 0x081eb420 consume the r0:r1 residue"
        );
        assert_eq!(
            unsafe { core::ptr::addr_of!(TIMESTAMP_BASELINE).read() },
            0x0012_3456_789a_bcdei64 << 10,
            "the scaled sample replaces the baseline slot (`strd r0,r1,[r2,#0x20]`)"
        );
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 1);
        assert_eq!(
            unsafe { BASELINE_SAMPLE_INTERFACE },
            0,
            "the original passes interface index 0 (`mov r0,#0x0`)"
        );
    }

    #[test]
    fn baseline_snapshot_shift_carries_across_the_word_boundary() {
        let _guard = install_recording_baseline_clock_sample(0x003f_ffff_ffff_ffff);
        let _reset = BaselineClockSampleReset;

        assert_eq!(
            unsafe { snapshot_timestamp_baseline() },
            0x003f_ffff_ffff_ffffi64 << 10,
            "the top ten bits of r0 must shift into r1 (`orr r1,r1,r0,lsr #0x16`)"
        );
        assert_eq!(
            unsafe { core::ptr::addr_of!(TIMESTAMP_BASELINE).read() },
            0x003f_ffff_ffff_ffffi64 << 10
        );
    }

    #[test]
    fn baseline_snapshot_overwrites_a_previous_baseline() {
        let _guard = install_recording_baseline_clock_sample(7);
        let _reset = BaselineClockSampleReset;

        assert_eq!(unsafe { snapshot_timestamp_baseline() }, 7 << 10);
        assert_eq!(unsafe { snapshot_timestamp_baseline() }, 7 << 10);
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 2);
    }

    #[test]
    fn zero_baseline_is_snapshotted_once_then_reused() {
        let _guard = install_recording_baseline_clock_sample(0x0012_3456_789a_bcde);
        let _reset = BaselineClockSampleReset;
        unsafe { core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(0) };

        assert_eq!(
            unsafe { timestamp_baseline() },
            0x0012_3456_789a_bcdei64 << 10,
            "a zero slot triggers the snapshot call (`cmpeq r0,r2` after `cmp r1,#0`)"
        );
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 1);
        assert_eq!(
            unsafe { core::ptr::addr_of!(TIMESTAMP_BASELINE).read() },
            0x0012_3456_789a_bcdei64 << 10,
            "the snapshot result is stored back into the slot (`strd r0,r1,[r4,#0x20]`)"
        );

        assert_eq!(
            unsafe { timestamp_baseline() },
            0x0012_3456_789a_bcdei64 << 10,
            "the populated slot is returned without resampling"
        );
        assert_eq!(
            unsafe { BASELINE_SAMPLE_CALLS },
            1,
            "the baseline is lazily sampled exactly once"
        );
    }

    #[test]
    fn nonzero_baseline_returns_without_sampling() {
        let _guard = install_recording_baseline_clock_sample(0x0012_3456_789a_bcde);
        let _reset = BaselineClockSampleReset;

        for baseline in [1, -1, i64::MIN, i64::MAX] {
            unsafe { core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(baseline) };

            assert_eq!(
                unsafe { timestamp_baseline() },
                baseline,
                "any nonzero doubleword short-circuits the lazy snapshot"
            );
        }
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 0);
    }

    #[test]
    fn resampling_after_zeroing_replaces_the_baseline() {
        let _guard = install_recording_baseline_clock_sample(3);
        let _reset = BaselineClockSampleReset;
        unsafe { core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(0) };

        assert_eq!(unsafe { timestamp_baseline() }, 3 << 10);

        unsafe {
            core::ptr::addr_of_mut!(TIMESTAMP_BASELINE).write(0);
            core::ptr::addr_of_mut!(MOCK_BASELINE_SAMPLE).write(9);
        }

        assert_eq!(unsafe { timestamp_baseline() }, 9 << 10);
        assert_eq!(unsafe { BASELINE_SAMPLE_CALLS }, 2);
    }
}

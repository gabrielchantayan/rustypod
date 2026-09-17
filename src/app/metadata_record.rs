//! `metadata_record_read_u32` — original: `FUN_0826863c` @ `0x0826863c`
//! (68 bytes).
//!
//! Serialized-record scalar reader of the track-metadata fetch framework
//! (the `0x08268xxx` decoder block; its diagnostics read "fetch metadata:
//! track id = %llu" and "metadata_size not being set by
//! metadata_for_global_id callback"). Every typed record decoder there
//! holds a reader object at self+0x04 and pulls its fixed u32 fields
//! through this helper.
//!
//! Assembly decoded from `work/firmware/osos.dec` @
//! `0x0826863c..0x08268680`:
//!
//! ```text
//! 0826863c  push {r3, lr}
//! 08268640  mov  r3, r0              @ reader
//! 08268644  ldr  r0, [r2]            @ *cursor
//! 08268648  ldr  r0, [r1, r0]        @ value = *(record + *cursor)
//! 0826864c  str  r0, [sp]            @ park on stack
//! 08268650  ldr  r0, [r2]
//! 08268654  add  r0, r0, #4
//! 08268658  str  r0, [r2]            @ *cursor += 4
//! 0826865c  ldr  r1, [r3]            @ reader->vtable
//! 08268660  ldr  r0, [r3, #4]        @ reader->engine
//! 08268664  ldr  ip, [r1, #32]       @ vtable slot +0x20
//! 08268668  mov  r1, sp              @ &value
//! 0826866c  mov  r3, #1              @ count = 1
//! 08268670  mov  r2, #4              @ elem_size = 4
//! 08268674  blx  ip                  @ transform(engine, &value, 4, 1)
//! 08268678  ldr  r0, [sp]            @ return transformed value
//! 0826867c  pop  {ip, pc}
//! ```
//!
//! Ghidra's 68-byte extent is exact: the sibling 8-byte variant
//! (`FUN_08268680`, same shape with `elem_size = 8`, cursor `+= 8`, `ldrd`
//! return) opens its `push {r2, r3, r4, lr}` prologue at `0x08268680`.
//!
//! Call count verified by decoding every B/BL word in osos.dec: exactly 23
//! call sites, ALL unconditional `bl`, zero predicated forms, zero tail
//! `b` references, and no data word in the image holds `0x0826863c` — the
//! helper is never dispatched virtually and callers never NULL-gate the
//! reader. Sites: 0x08268a90, 0x08268ab0, 0x08268c58, 0x08268d08,
//! 0x08268d1c, 0x08268d78, 0x08269054, 0x08269068, 0x0826907c,
//! 0x08269090, 0x082693e0, 0x082693f4, 0x08269408, 0x0826941c,
//! 0x0826953c, 0x08269550, 0x08269564, 0x08269578, 0x08269658,
//! 0x0826966c, 0x08269780, 0x08269794, 0x082697c8.
//!
//! # Algorithm
//!
//! 1. Load the u32 at `record + *cursor` into a stack local.
//! 2. Advance `*cursor` by 4.
//! 3. Invoke the reader's vtable slot +0x20 as
//!    `transform(reader->engine, &value, 4, 1)` — an in-place
//!    element-wise converter (element size / element count signature;
//!    the 0x08268680 sibling passes 8/1 and the vector path @
//!    0x0826850c-0x08268524 passes 8/N, so this is the framework's
//!    byte-order/normalization hook, not a copy). Its concrete engine is
//!    NOT identified — the call is a genuine virtual dispatch and no
//!    identity is invented here.
//! 4. Return the post-transform value.
//!
//! The cursor advances BEFORE the transform runs, so the transform always
//! observes the post-read cursor.
//!
//! Deliberate deviations: none structural. The record word load is a
//! plain aligned `u32` read (cursors only ever advance by 4/8 from zero
//! over word-aligned record buffers, so `read_unaligned`'s four-`ldrb`
//! idiom would be a pessimization, not a requirement).

/// Serialized-record reader object shared by the metadata decoders:
/// vtable at +0x00, opaque transform engine at +0x04. `#[repr(C)]`
/// pointer fields land at those exact byte offsets on the 32-bit target
/// and stay consistent for native host fixtures.
#[repr(C)]
pub struct MetadataRecordReader {
    /// Object vtable; slot +0x20 is the element transform.
    pub vtable: *const MetadataRecordReaderVtable,
    /// Opaque engine/context handed to the transform as its first
    /// argument.
    pub engine: *mut u8,
}

/// The part of the record-reader vtable recovered by this helper.
#[repr(C)]
pub struct MetadataRecordReaderVtable {
    /// Slots +0x00..+0x1f, dispatched by sibling helpers (e.g. the +0x18
    /// tail veneer @ 0x082686cc, vtable[6]) but unused here.
    pub unresolved_00: [usize; 8],
    /// Slot +0x20: in-place element transform over `count` elements of
    /// `elem_size` bytes at `elements`. Called here as
    /// `transform(engine, &value, 4, 1)`.
    pub transform_elements: unsafe extern "C" fn(
        engine: *mut u8,
        elements: *mut u8,
        elem_size: u32,
        count: u32,
    ),
}

/// metadata_record_read_u32 — original: `FUN_0826863c` @ `0x0826863c`
/// (68 bytes).
///
/// Reads the u32 field at `record + *cursor`, advances `*cursor` by 4,
/// runs the reader's virtual element transform on the value in place,
/// and returns the transformed value.
///
/// # Safety
///
/// `reader` must point at a live reader object whose vtable has a valid
/// +0x20 transform slot; `record + *cursor .. + 4` must be readable and
/// word-aligned; `cursor` must be a valid writable u32. The original has
/// no NULL guards and neither does the port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn metadata_record_read_u32(
    reader: *mut MetadataRecordReader,
    record: *const u8,
    cursor: *mut u32,
) -> u32 {
    unsafe {
        let offset = (*cursor) as usize;
        let mut value = record.add(offset).cast::<u32>().read();
        *cursor = (*cursor).wrapping_add(4);
        let vtable = (*reader).vtable;
        ((*vtable).transform_elements)(
            (*reader).engine,
            &mut value as *mut u32 as *mut u8,
            4,
            1,
        );
        value
    }
}

/// Context and vtable fragment used to release a fetched metadata record.
/// Both words are 4 bytes apart on the target; native function pointers keep
/// host fixtures callable without relying on target byte offsets.
#[repr(C)]
pub struct MetadataRecordReleaseContext {
    pub vtable: *const MetadataRecordReleaseVtable,
}

/// The release slot at context->vtable +0x0c.
#[repr(C)]
pub struct MetadataRecordReleaseVtable {
    pub unresolved_00: [usize; 3],
    pub release_record: Option<unsafe extern "C" fn(record: *mut u8)>,
}

/// metadata_record_release — original: `FUN_08268734` @ `0x08268734`
/// (28 bytes).
///
/// Raw ARM words at `0x08268734..0x08268750`:
///
/// ```text
/// 08268734  mov   r2, r0              @ context
/// 08268738  mov   r0, r1              @ record
/// 0826873c  ldr   r1, [r2]
/// 08268740  ldr   r1, [r1, #12]       @ vtable->release_record
/// 08268744  cmp   r1, #0
/// 08268748  beq   0x0802edc8          @ free(record)
/// 0826874c  bxne  r1                  @ release_record(record)
/// ```
///
/// The `bx lr` at `0x0826875c` closes
/// [`metadata_record_diagnostics_enabled`], not this function. The next
/// real function boundary is `0x08268750`, making the true extent 28 bytes;
/// Ghidra's 28-byte body incorrectly includes the far `beq` target as a
/// local block. A whole-image ARM branch-word decode found four direct calls,
/// all unconditional `bl` (0x082685b4, 0x08268c68, 0x08268d5c, 0x08268df4)
/// and zero predicated `bl` calls.
///
/// # Algorithm
///
/// Tail-dispatch the metadata record to the context vtable's +0x0c release
/// slot when present; otherwise tail-dispatch to the ported retailOS
/// [`crate::malloc_rt::free`]. The record is the second input register, not
/// the context Ghidra ascribes to the fallback call.
///
/// Deliberate deviations: Rust returns `()` rather than preserving the
/// undefined `r0` left by either tail callee; every verified caller ignores
/// it. The dispatch remains a direct call because Rust cannot express ARM's
/// register-only `bx` tail transfer.
///
/// # Safety
///
/// `context` must have a readable vtable word and the vtable must have a
/// readable +0x0c slot. If that slot is non-NULL it must accept `record`;
/// otherwise `record` must be acceptable to the retailOS allocator.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.metadata_record_release")]
#[inline(never)]
pub unsafe extern "C" fn metadata_record_release(
    context: *const MetadataRecordReleaseContext,
    record: *mut u8,
) {
    unsafe {
        match (*(*context).vtable).release_record {
            Some(release_record) => release_record(record),
            None => crate::malloc_rt::free(record),
        }
    }
}

#[cfg(test)]
mod release_tests {
    use super::*;

    unsafe extern "C" fn record_release(record: *mut u8) {
        unsafe { *(record.cast::<*mut u8>()) = record };
    }

    #[test]
    fn dispatches_non_null_release_slot_with_record_argument() {
        let vtable = MetadataRecordReleaseVtable {
            unresolved_00: [0; 3],
            release_record: Some(record_release),
        };
        let context = MetadataRecordReleaseContext { vtable: &vtable };
        let mut observed = core::ptr::null_mut();
        let record = &mut observed as *mut *mut u8 as *mut u8;

        unsafe { metadata_record_release(&context, record) };

        assert_eq!(observed, record);
    }

    #[test]
    fn null_release_slot_accepts_null_record_via_free_fallback() {
        let vtable = MetadataRecordReleaseVtable {
            unresolved_00: [0; 3],
            release_record: None,
        };
        let context = MetadataRecordReleaseContext { vtable: &vtable };

        unsafe { metadata_record_release(&context, core::ptr::null_mut()) };
    }
}
/// Track-metadata fetch context fields recovered by
/// `metadata_record_diagnostics_enabled`. `diagnostic_log` is the logging
/// context passed as the first argument to the diagnostic formatter by all
/// six direct callers.
///
/// `#[repr(C)]` preserves the three native-word fields at +0x00, +0x04,
/// and +0x08 on the 32-bit target without treating host byte offsets as
/// target offsets.
#[repr(C)]
pub struct MetadataRecordContext {
    pub unresolved_00: *mut u8,
    pub unresolved_04: *mut u8,
    pub diagnostic_log: *mut u8,
}

/// metadata_record_diagnostics_enabled — original: `FUN_08268750` @
/// `0x08268750` (16 bytes).
///
/// Raw ARM words at `0x08268750..0x08268760`:
///
/// ```text
/// 08268750  ldr   r0, [r0, #8]    @ context->diagnostic_log
/// 08268754  cmp   r0, #0
/// 08268758  movne r0, #1
/// 0826875c  bx    lr
/// ```
///
/// Returns whether the metadata-fetch context has a diagnostic log. This
/// gates the framework's verbose fetch-metadata, constraint-evaluation,
/// and teardown logging; it does not inspect or alter the log object.
///
/// The next function starts at `0x08268760` with `push {r0, r1, r2, r4,
/// r5, r6, r7, r8, r9, sl, fp, lr}`, so Ghidra's 16-byte extent is exact.
/// A whole-image ARM branch-word decode found six references, all
/// unconditional `bl` (0x082684dc, 0x0826852c, 0x082688c4, 0x08268918,
/// 0x08268d84, 0x08268ed8), with zero predicated calls and zero tail `b`
/// references. No firmware data word equals `0x08268750`, so it is not
/// virtually dispatched.
///
/// Deliberate deviations: none. As stock, this has no NULL guard for
/// `context`; dereferencing one faults.
///
/// # Safety
///
/// `context` must point to a live metadata-record fetch context. The
/// original immediately reads its diagnostic-log field.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.metadata_record_diagnostics_enabled")]
#[inline(never)]
pub unsafe extern "C" fn metadata_record_diagnostics_enabled(
    context: *const MetadataRecordContext,
) -> bool {
    unsafe { !(*context).diagnostic_log.is_null() }
}

#[cfg(test)]
mod diagnostics_enabled_tests {
    use super::*;

    #[test]
    fn false_when_diagnostic_log_is_null() {
        let context = MetadataRecordContext {
            unresolved_00: 0x10usize as *mut u8,
            unresolved_04: 0x20usize as *mut u8,
            diagnostic_log: core::ptr::null_mut(),
        };

        assert!(!unsafe { metadata_record_diagnostics_enabled(&context) });
    }

    #[test]
    fn true_for_non_null_diagnostic_log_regardless_of_other_fields() {
        let context = MetadataRecordContext {
            unresolved_00: core::ptr::null_mut(),
            unresolved_04: core::ptr::null_mut(),
            diagnostic_log: 0x30usize as *mut u8,
        };

        assert!(unsafe { metadata_record_diagnostics_enabled(&context) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorder the mock transform writes its observed arguments into;
    /// reached through the reader's opaque `engine` pointer, so no test
    /// globals are involved.
    struct TransformLog {
        calls: u32,
        elem_size: u32,
        count: u32,
        engine_seen: *mut u8,
        /// When nonzero, byteswap the element in place (models the
        /// framework's endian-conversion engine).
        swap: u32,
    }

    unsafe extern "C" fn recording_transform(
        engine: *mut u8,
        elements: *mut u8,
        elem_size: u32,
        count: u32,
    ) {
        unsafe {
            let log = &mut *(engine as *mut TransformLog);
            log.calls += 1;
            log.elem_size = elem_size;
            log.count = count;
            log.engine_seen = engine;
            if log.swap != 0 {
                let value = &mut *(elements as *mut u32);
                *value = value.swap_bytes();
            }
        }
    }

    fn fixture(swap: u32) -> (MetadataRecordReaderVtable, TransformLog) {
        (
            MetadataRecordReaderVtable {
                unresolved_00: [0; 8],
                transform_elements: recording_transform,
            },
            TransformLog { calls: 0, elem_size: 0, count: 0, engine_seen: core::ptr::null_mut(), swap },
        )
    }

    /// Words of a serialized record, word-aligned as on device.
    const RECORD: [u32; 4] = [0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00];

    #[test]
    fn reads_word_at_cursor_and_advances() {
        let (vtable, mut log) = fixture(1);
        let mut reader = MetadataRecordReader {
            vtable: &vtable,
            engine: &mut log as *mut TransformLog as *mut u8,
        };
        let engine_before = reader.engine;
        let mut cursor: u32 = 4;
        let value = unsafe {
            metadata_record_read_u32(&mut reader, RECORD.as_ptr() as *const u8, &mut cursor)
        };
        // Post-transform return: the in-place byteswap is visible.
        assert_eq!(value, 0x8877_6655);
        assert_eq!(cursor, 8);
        assert_eq!(log.calls, 1);
        assert_eq!(log.elem_size, 4);
        assert_eq!(log.count, 1);
        assert_eq!(log.engine_seen, engine_before);
    }

    #[test]
    fn identity_transform_returns_raw_word() {
        let (vtable, mut log) = fixture(0);
        let mut reader = MetadataRecordReader {
            vtable: &vtable,
            engine: &mut log as *mut TransformLog as *mut u8,
        };
        let mut cursor: u32 = 0;
        let value = unsafe {
            metadata_record_read_u32(&mut reader, RECORD.as_ptr() as *const u8, &mut cursor)
        };
        assert_eq!(value, 0x1122_3344);
        assert_eq!(cursor, 4);
        assert_eq!(log.calls, 1);
    }

    #[test]
    fn successive_reads_walk_the_record() {
        let (vtable, mut log) = fixture(0);
        let mut reader = MetadataRecordReader {
            vtable: &vtable,
            engine: &mut log as *mut TransformLog as *mut u8,
        };
        let mut cursor: u32 = 8;
        let first = unsafe {
            metadata_record_read_u32(&mut reader, RECORD.as_ptr() as *const u8, &mut cursor)
        };
        let second = unsafe {
            metadata_record_read_u32(&mut reader, RECORD.as_ptr() as *const u8, &mut cursor)
        };
        assert_eq!(first, 0x99aa_bbcc);
        assert_eq!(second, 0xddee_ff00);
        assert_eq!(cursor, 16);
        assert_eq!(log.calls, 2);
    }

    #[test]
    fn transform_runs_with_advanced_cursor() {
        // The original stores *cursor + 4 back before the blx; a transform
        // that could observe the cursor would see the advanced value.
        // Observable here only as: exactly one transform call per read,
        // and the returned value is the post-transform one even when the
        // transform overwrites unconditionally.
        unsafe extern "C" fn overwriting_transform(
            _engine: *mut u8,
            elements: *mut u8,
            _elem_size: u32,
            _count: u32,
        ) {
            unsafe { *(elements as *mut u32) = 0xdead_beef };
        }
        let vtable = MetadataRecordReaderVtable {
            unresolved_00: [0; 8],
            transform_elements: overwriting_transform,
        };
        let mut reader = MetadataRecordReader { vtable: &vtable, engine: core::ptr::null_mut() };
        let mut cursor: u32 = 12;
        let value = unsafe {
            metadata_record_read_u32(&mut reader, RECORD.as_ptr() as *const u8, &mut cursor)
        };
        assert_eq!(value, 0xdead_beef);
        assert_eq!(cursor, 16);
    }
}

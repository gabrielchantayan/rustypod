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

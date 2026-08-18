//! Packed-record deserialization — SQLite turns one index/row record
//! blob into the `UnpackedRecord` of typed `Mem` fields that
//! [`vdbe_record_compare`](super::vdbe_record_compare::vdbe_record_compare)
//! consumes.
//!
//! - `vdbe_record_unpack` — original: `FUN_0838c9f0` @ 0x0838c9f0
//!   (312 bytes, 0x0838c9f0..0x0838cb28). Upstream SQLite 3.5.9's
//!   `sqlite3VdbeRecordUnpack` (vdbeaux.c): `UnpackedRecord
//!   *sqlite3VdbeRecordUnpack(KeyInfo *pKeyInfo, int nKey, const void
//!   *pKey, void *pSpace, int szSpace)`, verified against the 3.5.9
//!   source. functions.csv's 312 bytes is exact: the next `stmdb` is
//!   0x0838cb28 and the function has no literal pool. **2 `bl` call
//!   sites** (binary-scanned from osos.dec): 0x08371f2c in
//!   FUN_08371e54 (the `sqlite3BtreeMoveto` analog) and 0x0838b430 in
//!   FUN_0838b380 (the `sqlite3VdbeIdxKeyCompare` analog) — both pass a
//!   200-byte stack buffer as `pSpace`; no tail `b`.
//!
//! ### Algorithm
//!
//! ```text
//! 0838c9f0:  stmdb  sp!,{r0-r11,lr}   ; r8=pKeyInfo r9=pKey
//! 0838c9f8:  ldr    r1,[r8,#0x8]      ; KeyInfo.nField
//! 0838ca00:  mov    r2,#0x28          ; sizeof(Mem)
//! 0838ca04:  add    r1,r1,#0x2
//! 0838ca10:  mul    r1,r2,r1          ; nByte = (nField+2)*sizeof(Mem)
//! 0838ca18:  cmp    r1,r0             ; r0 = szSpace ([sp,#0x40])
//! 0838ca1c:  movle  r4,r3             ; fits: p = pSpace
//! 0838ca24:  strble r11,[r3,#0x6]     ;   p->needFree = 0
//! 0838ca2c:  ldr    r0,[r8,#0x0]      ; else: KeyInfo.db
//! 0838ca30:  bl     0x08374960        ;   db_malloc_raw(db, nByte)
//! 0838ca34:  movs   r4,r0; beq out    ;   NULL propagates
//! 0838ca3c:  strb   r5,[r4,#0x6]      ;   p->needFree = 1
//! 0838ca40:  str    r8,[r4,#0x0]      ; p->pKeyInfo = pKeyInfo
//! 0838ca4c:  strh   r0,[r4,#0x4]      ; p->nField = nField+1 (u16)
//! 0838ca50:  strb   r5,[r4,#0x7]      ; p->needDestroy = 1
//! 0838ca54:  add    r5,r4,#0x28
//! 0838ca58:  str    r5,[r4,#0x8]      ; p->aMem = &((Mem*)p)[1]
//! ```
//!
//! Then the header-size varint is decoded with the build-wide idiom
//! (first byte < 0x80 inline — value = byte, length 1 — anything else
//! calls `sqlite3GetVarint` @ 0x0837ac30, ported, called directly, u64
//! out truncated to the original's u32 store) yielding `szHdr`; the
//! payload cursor `d` starts there and the header cursor `idx` right
//! after the varint. While `idx < szHdr` (unsigned) AND `i <
//! p->nField` (the u16 at +0x04, reloaded per iteration): decode the
//! next serial type the same way, break when the payload is exhausted
//! (`d >= nKey`, SIGNED `blt` to skip) and
//! [`vdbe_serial_type_len`] @ 0x0838cfe8 reports a nonzero length
//! (SIGNED `bgt` — exact, the table/formula never sets bit 31), else
//! seed the field `Mem` from the KeyInfo (`enc` byte +0x1f, `db` word
//! +0x10), clear `flags` (+0x1c hword) and `zMalloc` (+0x24 word), and
//! [`vdbe_serial_get`] @ 0x0838cc1c decodes the field into it (`d +=`
//! its return, `pMem += 0x28`). The exhausted-payload break means a
//! short record stops before the first field that would read past
//! `nKey`, but trailing zero-length fields (NULL, the 0/1 constants)
//! are still unpacked. Finally `p->nField = i` — the count actually
//! unpacked — and `p` is returned.
//!
//! Register usage: r0..r3 = pKeyInfo/nKey/pKey/pSpace, [sp,#0x40] =
//! szSpace; r4 = p, r5 = pMem, r6 = idx, r7 = d, r8 = pKeyInfo, r9 =
//! pKey, r10 = i, r11 = 0.
//!
//! ### Deviations
//!
//! - The `aMem` elements stay RAW original-layout 0x28-byte `Mem`s
//!   (the [`vdbe_serial_get`] convention): on a 64-bit test host the
//!   `db` word the port stamps at +0x10 is the pointer's low 32 bits,
//!   while on the ARM target it is the complete pointer — the
//!   original's `str r0,[r5,#0x10]` is a 4-byte store, and a
//!   host-width store would clobber the `z`/`n` slots at
//!   +0x14/+0x18.
//! - [`get_varint32_fast`](super::vdbe_record_compare::get_varint32_fast)
//!   is reused from `vdbe_record_compare` (one idiom, one home).
//! - [`db_malloc_raw`](super::mem::db_malloc_raw), [`vdbe_serial_get`]
//!   and [`vdbe_serial_type_len`] ARE ported and are called directly,
//!   per the porting rules.

use super::mem::db_malloc_raw;
use super::mem_release::Z_MALLOC_OFFSET;
use super::value_new::{MEM_DB_OFFSET, MEM_FLAGS_OFFSET, MEM_SIZE};
use super::value_text::MEM_ENC_OFFSET;
use super::vdbe_record_compare::{get_varint32_fast, KeyInfo, UnpackedRecord};
use super::vdbe_serial_get::vdbe_serial_get;
use super::vdbe_serial_type_len::vdbe_serial_type_len;

/// vdbe_record_unpack — original: `FUN_0838c9f0` @ 0x0838c9f0 (312
/// bytes; 2 `bl` call sites).
///
/// `sqlite3VdbeRecordUnpack`: parse the `n_key`-byte record at `p_key`
/// into an `UnpackedRecord` over `key_info`, using `p_space` when
/// `(nField + 2) * sizeof(Mem)` fits in `sz_space` bytes and
/// connection-owned heap memory otherwise. Returns NULL only when the
/// heap path is taken and the allocation fails. See the module header
/// for the original listing, the exhausted-payload break rule, and the
/// host raw-layout deviation.
///
/// # Safety
/// `key_info` must be a valid target-layout `KeyInfo`; its `db` field
/// is handed to [`db_malloc_raw`] when `p_space` is too small. `p_key`
/// must provide `n_key` readable bytes. `p_space`, when used, must be
/// writable for `(nField + 2) * 0x28` bytes; the returned `aMem`
/// fields alias `p_key`'s payload for text/blob serial types.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_record_unpack(
    key_info: *const KeyInfo,
    n_key: i32,
    p_key: *const u8,
    p_space: *mut u8,
    sz_space: i32,
) -> *mut UnpackedRecord {
    let n_byte = ((*key_info).n_field.wrapping_add(2)).wrapping_mul(MEM_SIZE);
    let p_ret = if n_byte <= sz_space {
        let p_ret = p_space as *mut UnpackedRecord;
        (*p_ret).need_free = 0;
        p_ret
    } else {
        let p_ret = db_malloc_raw((*key_info).db, n_byte) as *mut UnpackedRecord;
        if p_ret.is_null() {
            return core::ptr::null_mut();
        }
        (*p_ret).need_free = 1;
        p_ret
    };
    (*p_ret).key_info = key_info;
    (*p_ret).n_field = ((*key_info).n_field + 1) as u16;
    (*p_ret).need_destroy = 1;
    let mut p_mem = (p_ret as *mut u8).add(MEM_SIZE as usize);
    (*p_ret).a_mem = p_mem;

    let mut sz_hdr: u32 = 0;
    let mut idx = get_varint32_fast(p_key, &mut sz_hdr);
    let mut d = sz_hdr;
    let mut i: u32 = 0;
    while idx < sz_hdr && i < (*p_ret).n_field as u32 {
        let mut serial_type: u32 = 0;
        idx = idx.wrapping_add(get_varint32_fast(p_key.add(idx as usize), &mut serial_type));
        // Original: `cmp r7,r0; blt` (SIGNED d < nKey skips the check)
        // then `cmp r0,#0x0; bgt` (SIGNED length > 0 — the
        // table/formula never sets bit 31, so the signed read is
        // exact).
        if d as i32 >= n_key && vdbe_serial_type_len(serial_type) as i32 > 0 {
            break;
        }
        p_mem.add(MEM_ENC_OFFSET).write((*key_info).enc);
        (p_mem.add(MEM_DB_OFFSET) as *mut u32).write((*key_info).db as usize as u32);
        (p_mem.add(MEM_FLAGS_OFFSET) as *mut u16).write(0);
        (p_mem.add(Z_MALLOC_OFFSET) as *mut u32).write(0);
        d = d.wrapping_add(vdbe_serial_get(p_key.add(d as usize), serial_type, p_mem));
        p_mem = p_mem.add(MEM_SIZE as usize);
        i += 1;
    }
    (*p_ret).n_field = i as u16;
    p_ret
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::mem::tests::{install_recorder, realloc_log, Connection};
    use super::super::mem::{DB_MEM_OPS, DEFAULT_DB_MEM_OPS};
    use super::super::value_new::MEM_NULL;
    use super::*;
    use std::vec::Vec;

    /// 8-aligned buffer storage: `vdbe_serial_get` writes u64s into
    /// the field slots, and the 0x28 stride preserves the base
    /// alignment. Seeded with a nonzero pattern so a missed write
    /// leaves the seed, not a plausible zero.
    #[repr(align(8))]
    struct Aligned<const N: usize>([u8; N]);

    /// One record field: serial type plus its payload bytes (empty
    /// for NULL, the 0/1 constants and zero-length text/blob).
    struct Field {
        serial_type: u32,
        payload: Vec<u8>,
    }

    fn field(serial_type: u32, payload: &[u8]) -> Field {
        Field { serial_type, payload: payload.to_vec() }
    }

    /// Big-endian base-128, the subset the fixtures need.
    fn push_varint(out: &mut Vec<u8>, value: u32) {
        assert!(value < 0x4000, "fixtures stay below two varint bytes");
        if value < 0x80 {
            out.push(value as u8);
        } else {
            out.push(((value >> 7) | 0x80) as u8);
            out.push((value & 0x7f) as u8);
        }
    }

    fn varint_len(value: u32) -> usize {
        if value < 0x80 {
            1
        } else {
            2
        }
    }

    /// Builds `{header, payload}` from `fields`, reporting each
    /// field's payload offset. The header-size varint counts its own
    /// length, so its size is a fixpoint.
    fn build_record(fields: &[Field]) -> (Vec<u8>, Vec<usize>) {
        let types_len: usize = fields.iter().map(|f| varint_len(f.serial_type)).sum();
        let mut sz_hdr = types_len + 1;
        while varint_len(sz_hdr as u32) + types_len != sz_hdr {
            sz_hdr = varint_len(sz_hdr as u32) + types_len;
        }
        let mut record = Vec::new();
        push_varint(&mut record, sz_hdr as u32);
        for f in fields {
            push_varint(&mut record, f.serial_type);
        }
        let mut offsets = Vec::new();
        for f in fields {
            offsets.push(record.len());
            record.extend_from_slice(&f.payload);
        }
        (record, offsets)
    }

    /// A KeyInfo fixture; only `db`, `enc` and `n_field` are read by
    /// the code under test.
    fn key_info(db: *mut u8, enc: u8, n_field: i32) -> KeyInfo {
        KeyInfo {
            db,
            enc,
            incr_key: 0,
            prefix_is_equal: 0,
            _pad_07: 0,
            n_field,
            a_sort_order: core::ptr::null(),
            a_coll: [core::ptr::null(); 1],
        }
    }

    /// The reference model for one unpacked field: the same seed, the
    /// port's four pre-writes (enc/db, cleared flags/zMalloc), then
    /// the ported [`vdbe_serial_get`] over the same payload pointer —
    /// so a full 0x28-byte comparison catches any missed or stray
    /// write.
    unsafe fn ref_field_mem(
        seed: u8,
        record: &[u8],
        payload_off: usize,
        serial_type: u32,
        enc: u8,
        db: *mut u8,
    ) -> Aligned<0x28> {
        let mut expect = Aligned([seed; 0x28]);
        let p = expect.0.as_mut_ptr();
        p.add(MEM_ENC_OFFSET).write(enc);
        (p.add(MEM_DB_OFFSET) as *mut u32).write(db as usize as u32);
        (p.add(MEM_FLAGS_OFFSET) as *mut u16).write(0);
        (p.add(Z_MALLOC_OFFSET) as *mut u32).write(0);
        vdbe_serial_get(record.as_ptr().add(payload_off), serial_type, p);
        expect
    }

    /// Unpacks `record` into a caller buffer sized exactly
    /// `(n_field + 2) * 0x28`, returning the record, the payload
    /// offsets and the result pointer (which aliases `buf`).
    fn unpack_into_caller_buffer<'a, const N: usize>(
        fields: &[Field],
        key_info: &KeyInfo,
        buf: &'a mut Aligned<N>,
    ) -> (Vec<u8>, Vec<usize>, *mut UnpackedRecord) {
        let (record, offsets) = build_record(fields);
        let ret = unsafe {
            vdbe_record_unpack(
                key_info,
                record.len() as i32,
                record.as_ptr(),
                buf.0.as_mut_ptr(),
                N as i32,
            )
        };
        (record, offsets, ret)
    }

    /// Restore the real allocator slots while the OPS_LOCK guard is
    /// still held (the `sqlite/value_new.rs` convention).
    unsafe fn restore_allocator() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
    }

    const SENTINEL_DB: *mut u8 = 0x0bad_babeusize as *mut u8;

    #[test]
    fn caller_buffer_unpacks_every_serial_type() {
        let fields = [
            field(0, &[]),                                        // NULL
            field(1, &[0x80]),                                    // i8 -128
            field(2, &[0x12, 0x34]),                              // i16
            field(3, &[0xfe, 0xdc, 0xba]),                        // i24
            field(4, &[0xde, 0xad, 0xbe, 0xef]),                  // i32
            field(5, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),      // i48
            field(6, &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), // i64 max
            field(7, &3.25f64.to_be_bytes()),                     // REAL
            field(7, &f64::NAN.to_be_bytes()),                    // NaN -> NULL
            field(8, &[]),                                        // constant 0
            field(9, &[]),                                        // constant 1
            field(10, &[]),                                       // reserved
            field(11, &[]),                                       // reserved
            field(12, &[]),                                       // empty blob
            field(13, &[]),                                       // empty text
            field(23, b"hello"),                                  // 5-byte text
            field(26, &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]), // 7-byte blob
        ];
        let info = key_info(SENTINEL_DB, 1, fields.len() as i32);
        const N: usize = (17 + 2) * 0x28;
        let mut buf = Aligned([0xa5u8; N]);
        let (record, offsets, ret) = unpack_into_caller_buffer::<N>(&fields, &info, &mut buf);

        unsafe {
            assert_eq!(ret as *mut u8, buf.0.as_mut_ptr(), "pSpace is big enough");
            assert_eq!((*ret).key_info, &info as *const KeyInfo);
            assert_eq!((*ret).need_free, 0);
            assert_eq!((*ret).need_destroy, 1);
            assert_eq!((*ret).a_mem, buf.0.as_mut_ptr().add(0x28));
            assert_eq!((*ret).n_field as usize, fields.len());
            for (i, f) in fields.iter().enumerate() {
                let expect =
                    ref_field_mem(0xa5, &record, offsets[i], f.serial_type, 1, SENTINEL_DB);
                let actual = core::slice::from_raw_parts((*ret).a_mem.add(i * 0x28), 0x28);
                assert_eq!(
                    actual,
                    &expect.0[..],
                    "field {i} (serial type {}) round-trips through vdbe_serial_get",
                    f.serial_type
                );
            }
        }
    }

    #[test]
    fn exact_fit_uses_the_caller_buffer_one_byte_less_allocates() {
        let fields = [field(2, &[0x12, 0x34]), field(0, &[])];
        let (record, offsets) = build_record(&fields);
        const N: usize = (2 + 2) * 0x28;

        // Exact fit: no allocator involvement, pSpace used.
        let info = key_info(SENTINEL_DB, 1, 2);
        let mut buf = Aligned([0x5au8; N]);
        let ret = unsafe {
            vdbe_record_unpack(&info, record.len() as i32, record.as_ptr(), buf.0.as_mut_ptr(), N as i32)
        };
        assert_eq!(ret as *mut u8, buf.0.as_mut_ptr());
        unsafe {
            assert_eq!((*ret).need_free, 0);
        }

        // One byte short: db_malloc_raw(db, nByte) supplies the block.
        let mut block = Aligned([0x5au8; N]);
        let guard = install_recorder(block.0.as_mut_ptr());
        let mut conn = Connection::healthy();
        let info = key_info(conn.ptr(), 1, 2);
        let mut unused = Aligned([0x5au8; N]);
        unsafe {
            let ret = vdbe_record_unpack(
                &info,
                record.len() as i32,
                record.as_ptr(),
                unused.0.as_mut_ptr(),
                N as i32 - 1,
            );
            assert_eq!(ret as *mut u8, block.0.as_mut_ptr());
            assert_eq!((*ret).need_free, 1);
            assert_eq!((*ret).need_destroy, 1);
            assert_eq!((*ret).a_mem, block.0.as_mut_ptr().add(0x28));
            assert_eq!((*ret).n_field, 2);
            assert_eq!(
                realloc_log(),
                std::vec![(0, N as i32)],
                "one (nField + 2) * 0x28-byte allocation"
            );
            for (i, f) in fields.iter().enumerate() {
                let expect =
                    ref_field_mem(0x5a, &record, offsets[i], f.serial_type, 1, conn.ptr());
                let actual = core::slice::from_raw_parts((*ret).a_mem.add(i * 0x28), 0x28);
                assert_eq!(actual, &expect.0[..], "field {i} in the heap block");
            }
            restore_allocator();
        }
        drop(guard);
    }

    #[test]
    fn a_failed_allocation_returns_null_and_latches_the_flag() {
        let fields = [field(2, &[0x12, 0x34]), field(0, &[])];
        let (record, _) = build_record(&fields);
        const N: usize = (2 + 2) * 0x28;

        let guard = install_recorder(core::ptr::null_mut());
        let mut conn = Connection::healthy();
        let info = key_info(conn.ptr(), 1, 2);
        let mut unused = Aligned([0x5au8; N]);
        unsafe {
            let ret = vdbe_record_unpack(
                &info,
                record.len() as i32,
                record.as_ptr(),
                unused.0.as_mut_ptr(),
                N as i32 - 1,
            );
            assert!(ret.is_null(), "the malloc failure propagates");
            assert_eq!(realloc_log(), std::vec![(0, N as i32)]);
            assert_eq!(conn.failed_flag(), 1, "db_malloc_raw latches mallocFailed");
            restore_allocator();
        }
        drop(guard);
    }

    #[test]
    fn a_short_record_breaks_before_the_first_overrunning_field() {
        // Three 4-byte integers declared, payload for exactly one.
        let fields = [
            field(4, &[0x00, 0x00, 0x00, 0x01]),
            field(4, &[0x00, 0x00, 0x00, 0x02]),
            field(4, &[0x00, 0x00, 0x00, 0x03]),
        ];
        let (record, offsets) = build_record(&fields);
        let sz_hdr = offsets[0];
        let info = key_info(SENTINEL_DB, 1, 2);
        let mut buf = Aligned([0x5au8; (2 + 2) * 0x28]);
        unsafe {
            let ret = vdbe_record_unpack(
                &info,
                (sz_hdr + 4) as i32,
                record.as_ptr(),
                buf.0.as_mut_ptr(),
                buf.0.len() as i32,
            );
            assert_eq!((*ret).n_field, 1, "the second int would read past nKey");
            let expect = ref_field_mem(0x5a, &record, offsets[0], 4, 1, SENTINEL_DB);
            let actual = core::slice::from_raw_parts((*ret).a_mem, 0x28);
            assert_eq!(actual, &expect.0[..], "the one whole field still unpacks");
        }
    }

    #[test]
    fn an_exhausted_payload_still_unpacks_zero_length_fields() {
        // One 4-byte integer then two NULLs; nKey ends right after the
        // integer payload. serial_type_len(0) == 0, so the break does
        // not fire and both NULLs unpack.
        let fields = [field(4, &[0xde, 0xad, 0xbe, 0xef]), field(0, &[]), field(0, &[])];
        let (record, offsets) = build_record(&fields);
        let n_key = offsets[0] + 4;
        let info = key_info(SENTINEL_DB, 1, 2);
        let mut buf = Aligned([0x5au8; (2 + 2) * 0x28]);
        unsafe {
            let ret = vdbe_record_unpack(
                &info,
                n_key as i32,
                record.as_ptr(),
                buf.0.as_mut_ptr(),
                buf.0.len() as i32,
            );
            assert_eq!((*ret).n_field, 3, "trailing NULLs survive the exhausted payload");
            for i in 0..3 {
                let expect =
                    ref_field_mem(0x5a, &record, offsets[i], fields[i].serial_type, 1, SENTINEL_DB);
                let actual = core::slice::from_raw_parts((*ret).a_mem.add(i * 0x28), 0x28);
                assert_eq!(actual, &expect.0[..], "field {i}");
                if i > 0 {
                    let flags = ((*ret).a_mem.add(i * 0x28 + MEM_FLAGS_OFFSET)) as *const u16;
                    assert_eq!(flags.read(), MEM_NULL);
                }
            }
        }
    }

    #[test]
    fn the_field_cap_is_key_info_n_field_plus_one() {
        // Four NULLs in the header, but the KeyInfo admits only
        // nField + 1 = 2 fields.
        let fields = [field(0, &[]), field(0, &[]), field(0, &[]), field(0, &[])];
        let (record, _) = build_record(&fields);
        let info = key_info(SENTINEL_DB, 1, 1);
        let mut buf = Aligned([0x5au8; (1 + 2) * 0x28]);
        unsafe {
            let ret = vdbe_record_unpack(
                &info,
                record.len() as i32,
                record.as_ptr(),
                buf.0.as_mut_ptr(),
                buf.0.len() as i32,
            );
            assert_eq!((*ret).n_field, 2, "the header's extra types are ignored");
        }
    }

    #[test]
    fn a_two_byte_header_varint_takes_the_slow_path() {
        // 130 NULL fields: the one-byte guess 1 + 130 = 131 tips the
        // size varint to two bytes, so szHdr = 132 >= 0x80 and the
        // ported get_varint runs.
        let fields: Vec<Field> = (0..130).map(|_| field(0, &[])).collect();
        let (record, _) = build_record(&fields);
        assert_eq!(&record[..2], &[0x81, 0x04], "szHdr = 132 as a two-byte varint");
        let info = key_info(SENTINEL_DB, 1, 129);
        let mut buf = Aligned([0x5au8; (129 + 2) * 0x28]);
        unsafe {
            let ret = vdbe_record_unpack(
                &info,
                record.len() as i32,
                record.as_ptr(),
                buf.0.as_mut_ptr(),
                buf.0.len() as i32,
            );
            assert_eq!((*ret).n_field, 130);
            for i in 0..130 {
                let flags = ((*ret).a_mem.add(i * 0x28 + MEM_FLAGS_OFFSET)) as *const u16;
                assert_eq!(flags.read(), MEM_NULL, "field {i}");
            }
        }
    }

    #[test]
    fn a_two_byte_serial_type_takes_the_slow_path() {
        // Serial type 199 >= 0x80: a two-byte in-header varint and a
        // (199 - 12) >> 1 = 93-byte text payload.
        let text = std::vec![b'x'; 93];
        let fields = [field(199, &text), field(0, &[])];
        let (record, offsets) = build_record(&fields);
        let info = key_info(SENTINEL_DB, 1, 1);
        let mut buf = Aligned([0x5au8; (1 + 2) * 0x28]);
        unsafe {
            let ret = vdbe_record_unpack(
                &info,
                record.len() as i32,
                record.as_ptr(),
                buf.0.as_mut_ptr(),
                buf.0.len() as i32,
            );
            assert_eq!((*ret).n_field, 2);
            for (i, f) in fields.iter().enumerate() {
                let expect =
                    ref_field_mem(0x5a, &record, offsets[i], f.serial_type, 1, SENTINEL_DB);
                let actual = core::slice::from_raw_parts((*ret).a_mem.add(i * 0x28), 0x28);
                assert_eq!(actual, &expect.0[..], "field {i} (serial type {})", f.serial_type);
            }
        }
    }
}

//! Packed-record field serialization — the write-side twin of
//! [`vdbe_serial_get`](super::vdbe_serial_get): SQLite turns one `Mem`
//! into its serial-typed payload segment when OP_MakeRecord packs a
//! record.
//!
//! - `vdbe_serial_put` — original: `FUN_0838ce04` @ 0x0838ce04 (188
//!   bytes, 0x0838ce04..0x0838cec0; **1 `bl` call site**, binary-scanned
//!   from osos.dec: 0x08388840, inside the 16 KB VDBE engine routine
//!   FUN_08386ef8 — upstream vdbe.c's `sqlite3VdbeExec` OP_MakeRecord
//!   loop, which walks the Mem array at 0x28 stride and adds each
//!   field's packed length to its running offset). Upstream SQLite
//!   3.5.9's `sqlite3VdbeSerialPut` (vdbeaux.c): `u32
//!   sqlite3VdbeSerialPut(u8 *buf, int nBuf, Mem *pMem, int
//!   file_format)`. functions.csv's 188 bytes is exact: the 47th and
//!   final instruction is the return at 0x0838cebc, the next function's
//!   prologue (`stmdb sp!,{r4,r5,r6,lr}`) is 0x0838cec0 — the very
//!   callee this one dispatches to — and there is no literal pool.
//!
//! ### Listing
//!
//! ```text
//! 0838ce04  stmdb sp!, {r4,r5,r6,r7,r8,lr}
//! 0838ce08  mov  r7,r1              @ dst_capacity (nBuf)
//! 0838ce0c  mov  r6,r0              @ dst
//! 0838ce10  mov  r0,r2              @ p_mem
//! 0838ce14  mov  r1,r3              @ file_format
//! 0838ce18  mov  r4,r2              @ p_mem
//! 0838ce1c  bl   0x0838cec0         @ sqlite3VdbeSerialType(p_mem, file_format)
//! 0838ce20  sub  r1,r0,#0x1
//! 0838ce24  cmp  r1,#0x6
//! 0838ce28  bhi  0x0838ce64         @ outside 1..=7
//! 0838ce2c  cmp  r0,#0x7
//! 0838ce30  ldrdne r2,r3,[r4,#0x0]  @ integer: v = Mem.u.i
//! 0838ce34  ldrdeq r2,r3,[r4,#0x8]  @ real:    v = Mem.r bits
//! 0838ce38  bl   0x0838cfe8         @ sqlite3VdbeSerialTypeLen(serial_type)
//! 0838ce3c  mov  r1,r0              @ len
//! 0838ce40  sub  r0,r0,#0x1         @ i--
//! 0838ce44  cmn  r0,#0x1
//! 0838ce48  strbne r2,[r6,r0]       @ dst[i] = v & 0xff
//! 0838ce4c  movne r2,r2, lsr #0x8
//! 0838ce50  orrne r2,r2,r3, lsl #0x18  @ v >>= 8 (two-word funnel shift)
//! 0838ce54  movne r3,r3, lsr #0x8
//! 0838ce58  bne  0x0838ce40
//! 0838ce5c  mov  r0,r1              @ return len
//! 0838ce60  ldmia sp!, {r4,r5,r6,r7,r8,pc}
//! 0838ce64  cmp  r0,#0xc
//! 0838ce68  movcc r0,#0x0           @ types 0/8/9/10/11: no payload
//! 0838ce6c  ldmiacc sp!, {r4,r5,r6,r7,r8,pc}
//! 0838ce70  ldr  r5,[r4,#0x18]      @ n = Mem.n
//! 0838ce74  ldr  r1,[r4,#0x14]      @ Mem.z
//! 0838ce78  mov  r0,r6
//! 0838ce7c  mov  r2,r5
//! 0838ce80  bl   0x08037db0         @ __rt_memcpy(dst, z, n)
//! 0838ce84  ldrh r0,[r4,#0x1c]      @ Mem.flags
//! 0838ce88  tst  r0,#0x800          @ MEM_Zero?
//! 0838ce8c  beq  0x0838ceb8
//! 0838ce90  ldrd r0,r1,[r4,#0x0]    @ Mem.u.nZero (low word)
//! 0838ce94  adds r0,r0,r5
//! 0838ce98  adc  r1,r1,r5, asr #0x1f  @ dead high half (never read)
//! 0838ce9c  cmp  r0,r7
//! 0838cea0  mov  r5,r0              @ len = n + nZero
//! 0838cea4  ldr  r0,[r4,#0x18]      @ n, reloaded
//! 0838cea8  movgt r5,r7             @ clamp: len = min(len, nBuf), signed
//! 0838ceac  sub  r1,r5,r0
//! 0838ceb0  add  r0,r0,r6
//! 0838ceb4  bl   0x08037dc8         @ memzero(dst + n, len - n)
//! 0838ceb8  mov  r0,r5              @ return len
//! 0838cebc  ldmia sp!, {r4,r5,r6,r7,r8,pc}
//! ```
//!
//! ### Algorithm
//!
//! `sqlite3VdbeSerialType` @ 0x0838cec0 (UNPORTED — the
//! [`VDBE_SERIAL_PUT_OPS`] seam) classifies the `Mem`. Serial types
//! 1..=7 (the `sub r1,r0,#0x1; cmp r1,#0x6; bhi` dispatch) are the
//! fixed-width numeric arm: the value is the 64-bit `Mem.u.i` union
//! word at +0x00 — or the `Mem.r` binary64 bits at +0x08 when the type
//! is 7 — and the ported [`vdbe_serial_type_len`] supplies the byte
//! count; the store loop emits the low byte and funnel-shifts the
//! two-register value right by 8 until the index underflows, i.e.
//! big-endian, most-significant byte first. Types 0, 8, 9 and the
//! reserved 10/11 fall to `cmp r0,#0xc; movcc r0,#0x0` — they carry no
//! payload and return 0. Types at least 12 are the string/blob tail:
//! `Mem.n` (+0x18) bytes are copied from `Mem.z` (+0x14) through the
//! `__rt_memcpy` thunk @ 0x08037db0 (the ported [`__rt_memcpy`]), and a
//! `MEM_Zero` blob (+0x1c bit 0x800) then extends the length by
//! `Mem.u.nZero` (+0x00), clamps it to `nBuf` (signed `movgt`), and
//! zero-fills the extension through the `memzero` thunk @ 0x08037dc8
//! (the ported [`memzero`]). The return is the payload bytes written.
//!
//! ### Deviations
//!
//! - `p_mem` is the raw original-layout 0x28-byte `Mem`, exactly as in
//!   [`vdbe_serial_get`](super::vdbe_serial_get): on a 64-bit test host
//!   the 32-bit `z` word is the low half of the fixture pointer, so the
//!   string/blob tests map their payload below 4 GiB (see
//!   [`crate::testing::try_map_u32_slab`]); on the ARM target it is the
//!   complete pointer.
//! - The `nZero + n` sum is a 32-bit wrapping add: the original's
//!   `ldrd`/`adc` pair produces a 64-bit total whose high half feeds
//!   nothing (only the low word reaches the signed `cmp`/`movgt`
//!   clamp), so the observable behavior is the low word alone.
//! - The unported `sqlite3VdbeSerialType` @ 0x0838cec0 is dispatched
//!   through [`VDBE_SERIAL_PUT_OPS`]: the target default branches to
//!   the retail address, the host default is the loud
//!   [`missing_vdbe_serial_type`] stand-in (the `vdbe_record_compare`
//!   `mem_compare` pattern). The ported `sqlite3VdbeSerialTypeLen` @
//!   0x0838cfe8 is called DIRECTLY, per the house direct-call precedent
//!   for ported callees (`btree_parse_cell` → `get_varint`).

use crate::libc::memzero::memzero;
use crate::libc::rt_memcpy::__rt_memcpy;
use super::value_new::MEM_FLAGS_OFFSET;
use super::value_text::MEM_ZERO;
use super::vdbe_serial_get::{MEM_N_OFFSET, MEM_R_OFFSET, MEM_U_OFFSET, MEM_Z_OFFSET};
use super::vdbe_serial_type_len::vdbe_serial_type_len;

/// `sqlite3VdbeSerialType(p_mem, file_format)` @ 0x0838cec0: classify a
/// `Mem` into its record serial type (the low word of its r0:r1 pair;
/// the high word, the payload length, is unused here).
pub type VdbeSerialTypeFn = unsafe extern "C" fn(p_mem: *const u8, file_format: i32) -> u32;

/// RetailOS load address of `sqlite3VdbeSerialType`.
pub const VDBE_SERIAL_TYPE_ADDRESS: usize = 0x0838_cec0;

/// Target-side branch to the retail classifier (still unported).
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_serial_type(p_mem: *const u8, file_format: i32) -> u32 {
    let serial_type: VdbeSerialTypeFn = core::mem::transmute(VDBE_SERIAL_TYPE_ADDRESS);
    serial_type(p_mem, file_format)
}

/// The pre-port placeholder for the classifier slot: the host build has
/// no retail binary to branch to, so an unconfigured call fails loudly.
#[cfg(not(target_os = "none"))]
pub(crate) unsafe extern "C" fn missing_vdbe_serial_type(
    _p_mem: *const u8,
    _file_format: i32,
) -> u32 {
    panic!("vdbe_serial_put requires sqlite3VdbeSerialType @ 0x0838cec0")
}

/// Indirect dispatch for the unported serial-type classifier.
#[derive(Clone, Copy)]
pub struct VdbeSerialPutOps {
    /// `sqlite3VdbeSerialType(p_mem, file_format)` @ 0x0838cec0.
    pub serial_type: VdbeSerialTypeFn,
}

/// Target default: a branch to the retail classifier @ 0x0838cec0.
#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_SERIAL_PUT_OPS: VdbeSerialPutOps = VdbeSerialPutOps {
    serial_type: retail_vdbe_serial_type,
};

/// Host default: the loud stand-in, until a test installs its mock.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_SERIAL_PUT_OPS: VdbeSerialPutOps = VdbeSerialPutOps {
    serial_type: missing_vdbe_serial_type,
};

/// The active classifier. Host tests install recording mocks.
pub static mut VDBE_SERIAL_PUT_OPS: VdbeSerialPutOps = DEFAULT_VDBE_SERIAL_PUT_OPS;

/// Reads the classifier slot volatile so host replacements cannot be
/// folded into the default (the house pattern — `sqlite/cell_size.rs`).
#[inline(always)]
unsafe fn serial_type_op() -> VdbeSerialTypeFn {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_SERIAL_PUT_OPS.serial_type))
}

/// vdbe_serial_put — original: `FUN_0838ce04` @ 0x0838ce04 (188 bytes;
/// 1 `bl` call site, 0x08388840 inside FUN_08386ef8).
///
/// `sqlite3VdbeSerialPut`: serialize the raw 0x28-byte `Mem` at `p_mem`
/// into the record payload at `dst` (capacity `dst_capacity`), choosing
/// the encoding through the [`VDBE_SERIAL_PUT_OPS`] classifier, and
/// return the payload bytes written. See the module header for the
/// listing, the three dispatch arms, and the host raw-layout deviation.
///
/// Register usage: r0 = dst → return, r1 = dst_capacity/len, r2/r3 =
/// the value's two words, r4 = p_mem, r5 = len, r6 = dst, r7 =
/// dst_capacity.
///
/// # Safety
/// `p_mem` must point to a readable target-layout `Mem` whose `z` field
/// (for serial types at least 12) is a valid readable pointer for `n`
/// bytes. `dst` must be writable for the returned length; a `MEM_Zero`
/// blob additionally zero-fills up to the `dst_capacity` clamp.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_serial_put(
    dst: *mut u8,
    dst_capacity: i32,
    p_mem: *const u8,
    file_format: i32,
) -> u32 {
    let serial_type = serial_type_op()(p_mem, file_format);
    if serial_type.wrapping_sub(1) < 7 {
        let mut value = if serial_type == 7 {
            (p_mem.add(MEM_R_OFFSET) as *const u64).read()
        } else {
            (p_mem.add(MEM_U_OFFSET) as *const u64).read()
        };
        let len = vdbe_serial_type_len(serial_type);
        let mut index = len.wrapping_sub(1);
        while index != u32::MAX {
            *dst.add(index as usize) = value as u8;
            value >>= 8;
            index = index.wrapping_sub(1);
        }
        return len;
    }
    if serial_type >= 12 {
        let payload_len = (p_mem.add(MEM_N_OFFSET) as *const u32).read();
        let payload = (p_mem.add(MEM_Z_OFFSET) as *const u32).read() as *const u8;
        __rt_memcpy(dst, payload, payload_len as usize);
        let mut len = payload_len;
        if (p_mem.add(MEM_FLAGS_OFFSET) as *const u16).read() & MEM_ZERO != 0 {
            let zero_tail = (p_mem.add(MEM_U_OFFSET) as *const u32).read();
            len = zero_tail.wrapping_add(payload_len);
            if dst_capacity < len as i32 {
                len = dst_capacity as u32;
            }
            memzero(
                dst.add(payload_len as usize),
                len.wrapping_sub(payload_len) as usize,
            );
        }
        return len;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::value_new::MEM_SIZE;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the classifier slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every `(p_mem, file_format)` the classifier slot was called
    /// with, in order.
    static mut CALLS: Vec<(usize, i32)> = Vec::new();

    /// The serial type the installed mock reports.
    static mut MOCK_TYPE: u32 = 0;

    unsafe extern "C" fn recording_serial_type(p_mem: *const u8, file_format: i32) -> u32 {
        (*core::ptr::addr_of_mut!(CALLS)).push((p_mem as usize, file_format));
        *core::ptr::addr_of!(MOCK_TYPE)
    }

    /// Installs the recording mock reporting `serial_type`; restores
    /// the host defaults on drop.
    struct Fixture {
        _guard: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new(serial_type: u32) -> Fixture {
            let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                (*core::ptr::addr_of_mut!(CALLS)).clear();
                *core::ptr::addr_of_mut!(MOCK_TYPE) = serial_type;
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(VDBE_SERIAL_PUT_OPS),
                    VdbeSerialPutOps {
                        serial_type: recording_serial_type,
                    },
                );
            }
            Fixture { _guard: guard }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(VDBE_SERIAL_PUT_OPS),
                    DEFAULT_VDBE_SERIAL_PUT_OPS,
                );
            }
        }
    }

    fn calls() -> Vec<(usize, i32)> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// The payload arena must round-trip through the Mem's 32-bit `z`
    /// word, so it lives below 4 GiB (see `crate::testing`).
    static PAYLOAD_SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::VDBE_SERIAL_PUT, 0x1000).map(|p| p as usize));

    fn payload_slab() -> Option<*mut u8> {
        (*PAYLOAD_SLAB).map(|base| base as *mut u8)
    }

    /// A raw original-layout Mem, 8-aligned for the `ldrd` value loads.
    #[repr(align(8))]
    struct MemBlock([u8; MEM_SIZE as usize]);

    impl MemBlock {
        fn zeroed() -> MemBlock {
            MemBlock([0; MEM_SIZE as usize])
        }

        fn ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }

        fn put_u16(&mut self, offset: usize, value: u16) {
            self.0[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
        }

        fn put_u32(&mut self, offset: usize, value: u32) {
            self.0[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }

        fn put_u64(&mut self, offset: usize, value: u64) {
            self.0[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
    }

    /// Upstream's `aSize[]` — the very bytes the ported
    /// [`super::super::vdbe_serial_type_len`] module recovered from
    /// osos.dec; kept as an independent oracle here.
    const A_SIZE: [u32; 12] = [0, 1, 2, 3, 4, 6, 8, 8, 0, 0, 0, 0];

    unsafe fn rd_u16(p: *const u8, offset: usize) -> u16 {
        (p.add(offset) as *const u16).read()
    }

    unsafe fn rd_u32(p: *const u8, offset: usize) -> u32 {
        (p.add(offset) as *const u32).read()
    }

    unsafe fn rd_u64(p: *const u8, offset: usize) -> u64 {
        (p.add(offset) as *const u64).read()
    }

    /// Independent model of upstream 3.5.9's sqlite3VdbeSerialPut over
    /// a caller-supplied serial type.
    unsafe fn reference_serial_put(
        dst: *mut u8,
        dst_capacity: i32,
        p_mem: *const u8,
        serial_type: u32,
    ) -> u32 {
        if (1..=7).contains(&serial_type) {
            let mut value = if serial_type == 7 {
                rd_u64(p_mem, MEM_R_OFFSET)
            } else {
                rd_u64(p_mem, MEM_U_OFFSET)
            };
            let len = A_SIZE[serial_type as usize];
            for index in (0..len).rev() {
                *dst.add(index as usize) = (value & 0xff) as u8;
                value >>= 8;
            }
            return len;
        }
        if serial_type >= 12 {
            let n = rd_u32(p_mem, MEM_N_OFFSET);
            let z = rd_u32(p_mem, MEM_Z_OFFSET) as *const u8;
            core::ptr::copy_nonoverlapping(z, dst, n as usize);
            let mut len = n;
            if rd_u16(p_mem, MEM_FLAGS_OFFSET) & MEM_ZERO != 0 {
                let zero_tail = rd_u32(p_mem, MEM_U_OFFSET);
                len = zero_tail.wrapping_add(n);
                if dst_capacity < len as i32 {
                    len = dst_capacity as u32;
                }
                core::ptr::write_bytes(
                    dst.add(n as usize),
                    0,
                    len.wrapping_sub(n) as usize,
                );
            }
            return len;
        }
        0
    }

    /// Runs both implementations over `mem` with the mock reporting
    /// `serial_type`, asserting identical bytes and return. `dst` and
    /// `expected` start with identical filler so the untouched tail is
    /// compared too.
    unsafe fn put_against_reference(
        serial_type: u32,
        mem: &MemBlock,
        dst: &mut [u8],
        expected: &mut [u8],
        dst_capacity: i32,
    ) -> u32 {
        let actual_len = vdbe_serial_put(dst.as_mut_ptr(), dst_capacity, mem.ptr(), 4);
        let expected_len =
            reference_serial_put(expected.as_mut_ptr(), dst_capacity, mem.ptr(), serial_type);
        assert_eq!(actual_len, expected_len, "serial type {serial_type}");
        assert_eq!(dst, expected, "serial type {serial_type}");
        actual_len
    }

    #[test]
    fn integer_types_store_big_endian_and_report_their_width() {
        let values = [0x0102_0304_0506_0708u64, 0xff80_0000_ffff_007f, 0, u64::MAX];
        for serial_type in 1..=6u32 {
            let _fixture = Fixture::new(serial_type);
            let width = A_SIZE[serial_type as usize] as usize;
            for value in values {
                let mut mem = MemBlock::zeroed();
                mem.put_u64(MEM_U_OFFSET, value);
                let mut dst = [0xa5u8; 16];
                let mut expected = [0xa5u8; 16];
                unsafe {
                    put_against_reference(serial_type, &mem, &mut dst, &mut expected, 16);
                }
                assert_eq!(
                    &dst[..width],
                    &value.to_be_bytes()[8 - width..],
                    "serial type {serial_type} emits the value's low {width} bytes, MSB first"
                );
                assert!(
                    dst[width..].iter().all(|&b| b == 0xa5),
                    "serial type {serial_type} writes exactly its width"
                );
            }
        }
    }

    #[test]
    fn the_real_type_stores_the_ieee_bits_and_ignores_the_integer_word() {
        let _fixture = Fixture::new(7);
        let bits = 0xc005_bf0a_8b14_5769u64;
        let mut mem = MemBlock::zeroed();
        mem.put_u64(MEM_U_OFFSET, 0xdead_beef_dead_beef);
        mem.put_u64(MEM_R_OFFSET, bits);
        let mut dst = [0xa5u8; 16];
        let mut expected = [0xa5u8; 16];
        unsafe {
            put_against_reference(7, &mem, &mut dst, &mut expected, 16);
        }
        assert_eq!(&dst[..8], &bits.to_be_bytes(), "the +0x08 r word, big-endian");
        assert!(dst[8..].iter().all(|&b| b == 0xa5));
    }

    #[test]
    fn null_constants_and_reserved_types_write_nothing_and_return_zero() {
        for serial_type in [0u32, 8, 9, 10, 11] {
            let _fixture = Fixture::new(serial_type);
            let mem = MemBlock::zeroed();
            let mut dst = [0xa5u8; 16];
            let got = unsafe { vdbe_serial_put(dst.as_mut_ptr(), 16, mem.ptr(), 4) };
            assert_eq!(got, 0, "serial type {serial_type} has no payload");
            assert!(
                dst.iter().all(|&b| b == 0xa5),
                "serial type {serial_type} leaves the buffer untouched"
            );
        }
    }

    #[test]
    fn string_and_blob_types_copy_the_payload_and_report_n() {
        let Some(slab) = payload_slab() else {
            assert!(note_missing_u32_fixture("sqlite/vdbe_serial_put"));
            return;
        };
        let payload = b"hello-world";
        for (serial_type, flags) in [(12u32 + 2 * 11, 0x110u16), (13 + 2 * 11, 0x102)] {
            let _fixture = Fixture::new(serial_type);
            unsafe {
                core::ptr::copy_nonoverlapping(payload.as_ptr(), slab, payload.len());
            }
            let mut mem = MemBlock::zeroed();
            mem.put_u32(MEM_Z_OFFSET, slab as usize as u32);
            mem.put_u32(MEM_N_OFFSET, payload.len() as u32);
            mem.put_u16(MEM_FLAGS_OFFSET, flags);
            let mut dst = [0xa5u8; 32];
            let mut expected = [0xa5u8; 32];
            unsafe {
                put_against_reference(serial_type, &mem, &mut dst, &mut expected, 32);
            }
            assert_eq!(&dst[..payload.len()], payload);
            assert!(dst[payload.len()..].iter().all(|&b| b == 0xa5));
        }
    }

    #[test]
    fn a_zero_tail_blob_extends_with_zeros_and_reports_the_full_length() {
        let Some(slab) = payload_slab() else {
            assert!(note_missing_u32_fixture("sqlite/vdbe_serial_put"));
            return;
        };
        let payload = b"abcde";
        let zero_tail = 7u32;
        let _fixture = Fixture::new(12 + 2 * (payload.len() as u32 + zero_tail));
        unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), slab, payload.len());
        }
        let mut mem = MemBlock::zeroed();
        mem.put_u32(MEM_Z_OFFSET, slab as usize as u32);
        mem.put_u32(MEM_N_OFFSET, payload.len() as u32);
        mem.put_u16(MEM_FLAGS_OFFSET, 0x110 | MEM_ZERO);
        mem.put_u32(MEM_U_OFFSET, zero_tail);
        let mut dst = [0xa5u8; 32];
        let mut expected = [0xa5u8; 32];
        unsafe {
            put_against_reference(
                12 + 2 * (payload.len() as u32 + zero_tail),
                &mem,
                &mut dst,
                &mut expected,
                32,
            );
        }
        let total = payload.len() + zero_tail as usize;
        assert_eq!(&dst[..payload.len()], payload);
        assert!(
            dst[payload.len()..total].iter().all(|&b| b == 0),
            "the nZero extension is zero-filled"
        );
        assert!(dst[total..].iter().all(|&b| b == 0xa5));
    }

    #[test]
    fn the_zero_tail_clamps_to_the_buffer_capacity() {
        let Some(slab) = payload_slab() else {
            assert!(note_missing_u32_fixture("sqlite/vdbe_serial_put"));
            return;
        };
        let payload = b"abcde";
        let capacity = 9i32;
        let _fixture = Fixture::new(12 + 2 * 25);
        unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), slab, payload.len());
        }
        let mut mem = MemBlock::zeroed();
        mem.put_u32(MEM_Z_OFFSET, slab as usize as u32);
        mem.put_u32(MEM_N_OFFSET, payload.len() as u32);
        mem.put_u16(MEM_FLAGS_OFFSET, 0x110 | MEM_ZERO);
        mem.put_u32(MEM_U_OFFSET, 20);
        let mut dst = [0xa5u8; 32];
        let mut expected = [0xa5u8; 32];
        let got = unsafe {
            put_against_reference(12 + 2 * 25, &mem, &mut dst, &mut expected, capacity)
        };
        assert_eq!(got, capacity as u32, "the clamped length is the capacity");
        assert_eq!(&dst[..payload.len()], payload);
        assert!(
            dst[payload.len()..capacity as usize].iter().all(|&b| b == 0),
            "only capacity - n bytes are zero-filled"
        );
        assert!(dst[capacity as usize..].iter().all(|&b| b == 0xa5));
    }

    #[test]
    fn the_classifier_seam_receives_the_mem_and_file_format_verbatim() {
        let _fixture = Fixture::new(0);
        let mem = MemBlock::zeroed();
        let mut dst = [0u8; 8];
        unsafe {
            vdbe_serial_put(dst.as_mut_ptr(), 8, mem.ptr(), 4);
        }
        assert_eq!(
            calls(),
            std::vec![(mem.ptr() as usize, 4)],
            "one classifier call with the original r0/r1"
        );
    }

    #[test]
    fn the_host_default_is_the_loud_missing_stand_in() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            DEFAULT_VDBE_SERIAL_PUT_OPS.serial_type as usize,
            missing_vdbe_serial_type as usize,
            "0x0838cec0 is unported: the host default fails loudly",
        );
        unsafe {
            assert_eq!(
                serial_type_op() as usize,
                missing_vdbe_serial_type as usize,
                "the live slot ships the stand-in too",
            );
        }
    }
}

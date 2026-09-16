//! `scaled_byte_pair_record_construct` — original: `FUN_083d2328` @
//! 0x083d2328 (92 bytes; **4 unconditional `bl` call sites** — 0x08269840,
//! 0x08269994, 0x082699c8, 0x0826a5d8 — counted by decoding every ARM B/BL
//! immediate word in `osos.dec`; there are no predicated `bl` forms, no tail
//! `b` transfers, and no aligned data-word references to the entry).
//!
//! # Extent, binary-verified
//!
//! The raw body is exactly 23 words from `push {r4,r5,r6,r7,r8,lr}` at
//! 0x083d2328 through `pop {r4,r5,r6,r7,r8,pc}` at 0x083d2380; the next
//! function is the already-ported `byte_pair_prefix_init` at 0x083d2384, so
//! Ghidra's 92-byte extent is exact and there is no literal pool.
//!
//! # Algorithm
//!
//! Constructs a 0x24-byte record in place (all four callers allocate it via
//! the `operator new`-like `FUN_082aadd4(0x24)`):
//!
//! 1. `byte_pair_prefix_init(this, a, b)` writes the duplicated low-byte
//!    header at +0x00..+0x08 (`*a, *b, *a, *b`, then a zero word).
//! 2. Stores `1.0f` (0x3f800000 — the `e3a015fe` word is
//!    `mov r1, #0xfe ROR 10`) at +0x08 and zero at +0x14.
//! 3. Stores `table_lookup(key)` at +0x18, where `table_lookup` is the
//!    firmware helper at 0x0826f3bc (a binary search over a 40-entry sorted
//!    u32 table, entry `push {r1-r4,lr}`, exit `pop {r1-r4,pc}`; all four
//!    callers pass key 0x32).
//! 4. Zeroes +0x1c and +0x20.
//! 5. Calls the sub-record initializer at 0x083d351c with `this + 0x10`
//!    (it allocates a `(n+1)*4` word array through the unported allocator
//!    0x08266c70 and threads a self-referential cursor at +0x1c of the
//!    sub-record).
//! 6. Calls the finalizer at 0x083d2e44 with `this`; it computes
//!    `+0x0c = double_to_u32_saturating(ceil(__dmul(__f2d(+0x08),
//!    __u2d(+0x18))))` — the scale times the table value, rounded up.
//! 7. Returns `this` unchanged in r0.
//!
//! The record therefore pairs a two-tag byte header with a float scale and
//! a scale-derived saturated count; no caller-supplied class identity is
//! recoverable, so the name states only this verified structure.
//!
//! # Deliberate deviations
//!
//! The three callees other than `byte_pair_prefix_init` are unported
//! firmware functions. They are reached through the
//! [`SCALED_BYTE_PAIR_RECORD_OPS`] seam (firmware addresses via
//! `transmute` on target, panics on host — the `string_view.rs` /
//! `container_view.rs` split), never given invented identities: 0x0826f3bc
//! is named only `table_lookup` (its decoded behavior), and 0x083d351c /
//! 0x083d2e44 only `init_subrecord` / `finalize`. The existing names.yaml
//! `identified` entry for 0x0826f3bc (an interior "binary search tail" of
//! 0x0826f340) is contradicted by the raw words — 0x0826f3bc opens with
//! `push {r1,r2,r3,r4,lr}` and closes with `pop {r1,r2,r3,r4,pc}`, a
//! complete standalone function — but porting it is out of scope here; the
//! seam preserves the stock call. Word stores use `write_volatile` so LLVM
//! keeps them as single `str`s in the original order.

use crate::cxx::byte_pair_prefix_init::byte_pair_prefix_init;

/// Firmware address of the sorted-table binary-search helper (returns the
/// table value for `key`; complete function `push {r1-r4,lr}` ..
/// `pop {r1-r4,pc}`).
pub const TABLE_LOOKUP_ADDRESS: usize = 0x0826_f3bc;
/// Firmware address of the sub-record initializer at record +0x10.
pub const INIT_SUBRECORD_ADDRESS: usize = 0x083d_351c;
/// Firmware address of the finalizer that derives record +0x0c.
pub const FINALIZE_ADDRESS: usize = 0x083d_2e44;

/// Seams to the three unported firmware callees.
pub struct ScaledBytePairRecordOps {
    /// 0x0826f3bc: sorted-table lookup, `key` in r0, value returned in r0.
    pub table_lookup: unsafe extern "C" fn(key: u32) -> u32,
    /// 0x083d351c: initializes the sub-record at `this + 0x10`.
    pub init_subrecord: unsafe extern "C" fn(subrecord: *mut u8),
    /// 0x083d2e44: derives record +0x0c from +0x08 and +0x18.
    pub finalize: unsafe extern "C" fn(this: *mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_table_lookup(key: u32) -> u32 {
    let lookup: unsafe extern "C" fn(u32) -> u32 =
        unsafe { core::mem::transmute(TABLE_LOOKUP_ADDRESS) };
    unsafe { lookup(key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_table_lookup(_key: u32) -> u32 {
    panic!("scaled_byte_pair_record_construct requires table lookup 0x0826f3bc")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_init_subrecord(subrecord: *mut u8) {
    let init: unsafe extern "C" fn(*mut u8) =
        unsafe { core::mem::transmute(INIT_SUBRECORD_ADDRESS) };
    unsafe { init(subrecord) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_init_subrecord(_subrecord: *mut u8) {
    panic!("scaled_byte_pair_record_construct requires sub-record init 0x083d351c")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_finalize(this: *mut u8) {
    let finalize: unsafe extern "C" fn(*mut u8) =
        unsafe { core::mem::transmute(FINALIZE_ADDRESS) };
    unsafe { finalize(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_finalize(_this: *mut u8) {
    panic!("scaled_byte_pair_record_construct requires finalizer 0x083d2e44")
}

/// Wired defaults: firmware addresses on target, panics on host; host
/// tests swap in recorders and restore these.
pub const DEFAULT_SCALED_BYTE_PAIR_RECORD_OPS: ScaledBytePairRecordOps =
    ScaledBytePairRecordOps {
        #[cfg(target_os = "none")]
        table_lookup: firmware_table_lookup,
        #[cfg(not(target_os = "none"))]
        table_lookup: missing_table_lookup,
        #[cfg(target_os = "none")]
        init_subrecord: firmware_init_subrecord,
        #[cfg(not(target_os = "none"))]
        init_subrecord: missing_init_subrecord,
        #[cfg(target_os = "none")]
        finalize: firmware_finalize,
        #[cfg(not(target_os = "none"))]
        finalize: missing_finalize,
    };

/// The active dispatch table. Host tests swap in recorders and restore the
/// defaults.
pub static mut SCALED_BYTE_PAIR_RECORD_OPS: ScaledBytePairRecordOps =
    DEFAULT_SCALED_BYTE_PAIR_RECORD_OPS;

/// In-place 0x24-byte layout written by the constructor (target pointer
/// width; the +0x10 sub-record and +0x0c count are completed by the
/// firmware callees, not by this function).
#[repr(C)]
pub struct ScaledBytePairRecord {
    /// +0x00..+0x04: duplicated low-byte header `*a, *b, *a, *b`.
    pub header: [u8; 4],
    /// +0x04..+0x08: zero word from `byte_pair_prefix_init`.
    pub header_zero: u32,
    /// +0x08: scale, always 1.0f at construction.
    pub scale: u32,
    /// +0x0c: saturated scaled count, written by the finalizer.
    pub scaled_count: u32,
    /// +0x10: sub-record word, initialized by the sub-record callee.
    pub subrecord: u32,
    /// +0x14: cleared here.
    pub zero_14: u32,
    /// +0x18: table value for `key`.
    pub table_value: u32,
    /// +0x1c and +0x20: cleared here.
    pub zero_1c: u32,
    pub zero_20: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(ScaledBytePairRecord, header)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ScaledBytePairRecord, scale)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(ScaledBytePairRecord, scaled_count)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(ScaledBytePairRecord, subrecord)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(ScaledBytePairRecord, zero_14)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(ScaledBytePairRecord, table_value)];
const _: [u8; 0x1c] = [0; core::mem::offset_of!(ScaledBytePairRecord, zero_1c)];
const _: [u8; 0x20] = [0; core::mem::offset_of!(ScaledBytePairRecord, zero_20)];

/// Constructs the 0x24-byte scaled byte-pair record at `this` and returns
/// `this`.
///
/// # Safety
///
/// `this` must be writable for 0x24 bytes and four-byte aligned for word
/// stores; `a` and `b` must each be readable for one byte. The installed
/// [`SCALED_BYTE_PAIR_RECORD_OPS`] slots must be callable with `key`,
/// `this + 0x10`, and `this` respectively. The retail constructor has no
/// NULL or alignment guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scaled_byte_pair_record_construct(
    this: *mut u8,
    key: u32,
    a: *const u8,
    b: *const u8,
) -> *mut u8 {
    let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCALED_BYTE_PAIR_RECORD_OPS)) };
    unsafe {
        byte_pair_prefix_init(this, a, b);
        this.add(0x08).cast::<u32>().write_volatile(0x3f80_0000);
        this.add(0x14).cast::<u32>().write_volatile(0);
        let table_value = (ops.table_lookup)(key);
        this.add(0x18).cast::<u32>().write_volatile(table_value);
        this.add(0x1c).cast::<u32>().write_volatile(0);
        this.add(0x20).cast::<u32>().write_volatile(0);
        (ops.init_subrecord)(this.add(0x10));
        (ops.finalize)(this);
    }
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset_ops() {
        unsafe { SCALED_BYTE_PAIR_RECORD_OPS = DEFAULT_SCALED_BYTE_PAIR_RECORD_OPS };
    }

    #[repr(C, align(4))]
    struct RecordBytes([u8; 0x24]);

    unsafe fn word_at(record: *const u8, offset: usize) -> u32 {
        unsafe { record.add(offset).cast::<u32>().read() }
    }

    static mut LOOKUP_ARG: u32 = 0;
    static mut LOOKUP_RESULT: u32 = 0;
    static mut SUBRECORD_ARG: *mut u8 = core::ptr::null_mut();
    static mut FINALIZE_ARG: *mut u8 = core::ptr::null_mut();
    static mut CALL_ORDER: [u8; 3] = [0; 3];
    static mut CALL_INDEX: usize = 0;

    unsafe extern "C" fn recording_table_lookup(key: u32) -> u32 {
        unsafe {
            LOOKUP_ARG = key;
            CALL_ORDER[CALL_INDEX] = b'L';
            CALL_INDEX += 1;
            LOOKUP_RESULT
        }
    }

    unsafe extern "C" fn recording_init_subrecord(subrecord: *mut u8) {
        unsafe {
            SUBRECORD_ARG = subrecord;
            CALL_ORDER[CALL_INDEX] = b'I';
            CALL_INDEX += 1;
        }
    }

    unsafe extern "C" fn recording_finalize(this: *mut u8) {
        unsafe {
            FINALIZE_ARG = this;
            CALL_ORDER[CALL_INDEX] = b'F';
            CALL_INDEX += 1;
        }
    }

    fn install_recorders(table_value: u32) {
        unsafe {
            LOOKUP_ARG = 0;
            LOOKUP_RESULT = table_value;
            SUBRECORD_ARG = core::ptr::null_mut();
            FINALIZE_ARG = core::ptr::null_mut();
            CALL_ORDER = [0; 3];
            CALL_INDEX = 0;
            SCALED_BYTE_PAIR_RECORD_OPS = ScaledBytePairRecordOps {
                table_lookup: recording_table_lookup,
                init_subrecord: recording_init_subrecord,
                finalize: recording_finalize,
            };
        }
    }

    #[test]
    fn initializes_all_fields_and_returns_this() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_ops();
        install_recorders(0x0bad_cafe);
        let mut record = RecordBytes([0xa5; 0x24]);
        let this = record.0.as_mut_ptr();
        let a: u8 = 0x11;
        let b: u8 = 0x22;

        let returned = unsafe { scaled_byte_pair_record_construct(this, 0x32, &a, &b) };

        assert_eq!(returned, this);
        assert_eq!(&record.0[0..4], &[0x11, 0x22, 0x11, 0x22]);
        assert_eq!(unsafe { word_at(this, 0x04) }, 0);
        assert_eq!(unsafe { word_at(this, 0x08) }, 0x3f80_0000);
        assert_eq!(unsafe { word_at(this, 0x14) }, 0);
        assert_eq!(unsafe { word_at(this, 0x18) }, 0x0bad_cafe);
        assert_eq!(unsafe { word_at(this, 0x1c) }, 0);
        assert_eq!(unsafe { word_at(this, 0x20) }, 0);
        assert_eq!(unsafe { LOOKUP_ARG }, 0x32);
        assert_eq!(unsafe { SUBRECORD_ARG }, unsafe { this.add(0x10) });
        assert_eq!(unsafe { FINALIZE_ARG }, this);
        // Lookup precedes sub-record init, which precedes the finalizer.
        assert_eq!(unsafe { CALL_ORDER }, *b"LIF");
        // +0x0c and +0x10 are the callees' responsibility: untouched here.
        assert_eq!(record.0[0x0c..0x10], [0xa5; 4]);
        assert_eq!(record.0[0x10..0x14], [0xa5; 4]);
        reset_ops();
    }

    #[test]
    fn key_is_forwarded_and_table_value_stored_verbatim() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_ops();
        install_recorders(u32::MAX);
        let mut record = RecordBytes([0; 0x24]);
        let a: u8 = 0;
        let b: u8 = 0;

        unsafe {
            scaled_byte_pair_record_construct(record.0.as_mut_ptr(), 0xdead_beef, &a, &b)
        };

        assert_eq!(unsafe { LOOKUP_ARG }, 0xdead_beef);
        assert_eq!(unsafe { word_at(record.0.as_ptr(), 0x18) }, u32::MAX);
        reset_ops();
    }

}

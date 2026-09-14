//! `itunesdb_read_default_field` — original: `FUN_080d8d14` @ `0x080d8d14`
//! (76 bytes, `0x080d8d14..0x080d8d60`; the separately linked next function
//! begins at `0x080d8d60`).
//!
//! Raw ARM decoding finds **6 direct `bl` callers**, all unconditional:
//! `0x08095c70`, `0x08095ca4`, `0x08095cf0`, `0x08095d40`, `0x08095d8c`, and
//! `0x08095fb8`. There are no predicated direct calls or tail branches.
//!
//! The wrapper forwards its seven arguments to unported `FUN_080be330`, adding
//! a zero fourth argument and a one ninth argument. The caller at `0x080952c4`
//! parses iTunesDB `mhlt`/`mhit` records, which establishes this wrapper's
//! iTunesDB field-read role. Ghidra's `void` return type is wrong: the raw
//! epilogue leaves the helper result in `r0`, and every caller consumes it.
//!
//! Deliberate deviation: `FUN_080be330` is not ported. Target builds call its
//! verified retailOS address; host tests use a volatile seam to make the full
//! nine-argument ABI and fixed defaults observable.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

#[cfg(test)]
extern crate std;

const RETAIL_ITUNESDB_FIELD_READ: usize = 0x080b_e330;

/// ABI of the unported generalized iTunesDB field reader at `0x080be330`.
pub type ItunesDbFieldRead = unsafe extern "C" fn(
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
) -> u32;

/// Host operations for the unported generalized field reader.
#[derive(Clone, Copy)]
pub struct ItunesDbFieldReadOps {
    pub read: ItunesDbFieldRead,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_itunesdb_field_read(
    _reader: u32,
    _mode: u32,
    _record: u32,
    _reserved: u32,
    _destination: u32,
    _field: u32,
    _field_type: u32,
    _enabled: u32,
    _finalize: u32,
) -> u32 {
    panic!("install iTunesDB field-read host operations before calling this wrapper")
}

/// Host default before a test installs the retail helper equivalent.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_ITUNESDB_FIELD_READ_OPS: ItunesDbFieldReadOps = ItunesDbFieldReadOps {
    read: missing_itunesdb_field_read,
};

/// Host-side generalized field-read seam. Target builds call `0x080be330`.
#[cfg(not(target_os = "none"))]
pub static mut ITUNESDB_FIELD_READ_OPS: ItunesDbFieldReadOps = DEFAULT_ITUNESDB_FIELD_READ_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_itunesdb_field_read(
    reader: u32,
    mode: u32,
    record: u32,
    reserved: u32,
    destination: u32,
    field: u32,
    field_type: u32,
    enabled: u32,
    finalize: u32,
) -> u32 {
    let read: ItunesDbFieldRead = core::mem::transmute(RETAIL_ITUNESDB_FIELD_READ);
    read(
        reader,
        mode,
        record,
        reserved,
        destination,
        field,
        field_type,
        enabled,
        finalize,
    )
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_itunesdb_field_read(
    reader: u32,
    mode: u32,
    record: u32,
    reserved: u32,
    destination: u32,
    field: u32,
    field_type: u32,
    enabled: u32,
    finalize: u32,
) -> u32 {
    let read = core::ptr::read_volatile(addr_of!(ITUNESDB_FIELD_READ_OPS.read));
    read(
        reader,
        mode,
        record,
        reserved,
        destination,
        field,
        field_type,
        enabled,
        finalize,
    )
}

/// Reads one iTunesDB field with the stock wrapper's fixed helper defaults.
///
/// # Safety
///
/// All arguments are target-width opaque values and must satisfy the
/// unported generalized reader's contract. The stock wrapper has no guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn itunesdb_read_default_field(
    reader: u32,
    mode: u32,
    record: u32,
    destination: u32,
    field: u32,
    field_type: u32,
    enabled: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    return retail_itunesdb_field_read(
        reader,
        mode,
        record,
        0,
        destination,
        field,
        field_type,
        enabled,
        1,
    );

    #[cfg(not(target_os = "none"))]
    host_itunesdb_field_read(
        reader,
        mode,
        record,
        0,
        destination,
        field,
        field_type,
        enabled,
        1,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static FIELD_READ_OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut FIELD_READ_CALL: Option<[u32; 9]> = None;

    unsafe extern "C" fn record_field_read(
        reader: u32,
        mode: u32,
        record: u32,
        reserved: u32,
        destination: u32,
        field: u32,
        field_type: u32,
        enabled: u32,
        finalize: u32,
    ) -> u32 {
        FIELD_READ_CALL = Some([
            reader,
            mode,
            record,
            reserved,
            destination,
            field,
            field_type,
            enabled,
            finalize,
        ]);
        0x7a31_c0de
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = FIELD_READ_OPS_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(FIELD_READ_CALL).write(None);
            addr_of_mut!(ITUNESDB_FIELD_READ_OPS).write(ItunesDbFieldReadOps {
                read: record_field_read,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(ITUNESDB_FIELD_READ_OPS).write(DEFAULT_ITUNESDB_FIELD_READ_OPS);
        }
        drop(guard);
    }

    #[test]
    fn forwards_all_arguments_and_stock_helper_defaults() {
        let guard = install_recorder();

        let result = unsafe {
            itunesdb_read_default_field(
                0x1111_1111,
                0x2222_2222,
                0x3333_3333,
                0x4444_4444,
                0x5555_5555,
                0x6666_6666,
                0,
            )
        };

        unsafe {
            assert_eq!(
                addr_of!(FIELD_READ_CALL).read(),
                Some([
                    0x1111_1111,
                    0x2222_2222,
                    0x3333_3333,
                    0,
                    0x4444_4444,
                    0x5555_5555,
                    0x6666_6666,
                    0,
                    1,
                ])
            );
        }
        assert_eq!(result, 0x7a31_c0de);
        restore_default(guard);
    }

    #[test]
    fn preserves_nonzero_enabled_argument_and_reader_result() {
        let guard = install_recorder();

        let result = unsafe { itunesdb_read_default_field(1, 2, 3, 4, 5, 6, 0xffff_ffff) };

        unsafe {
            assert_eq!(
                addr_of!(FIELD_READ_CALL).read(),
                Some([1, 2, 3, 0, 4, 5, 6, 0xffff_ffff, 1])
            );
        }
        assert_eq!(result, 0x7a31_c0de);
        restore_default(guard);
    }
}

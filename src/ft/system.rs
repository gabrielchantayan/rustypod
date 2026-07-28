//! FreeType's `ftsystem.c` — the platform seam, which on this device is
//! Apple's own rather than upstream's ANSI/stdio one. Upstream ships
//! `FT_Stream_Open` next to an `ft_ansi_stream_io`/`ft_ansi_stream_close`
//! pair built on `FILE*`; this build ships exactly that shape, three
//! functions in a row, over the firmware's C++ file object:
//!
//! ```text
//! 0x082d3d40  close callback  ->  stream->close
//! 0x082d3d7c  read  callback  ->  stream->read
//! 0x082d3ddc  the opener      ->  called by FT_Stream_Open @ 0x0804f338
//! ```
//!
//! [`ft_platform_stream_open`] is the third of those. It is the reason
//! this is *not* upstream code: it splits the path FreeType hands it into
//! a volume digit and a path (`"0:/Foo/Bar"` -> volume 0, `"/Foo/Bar"`),
//! asks the firmware to open it, and only then fills in the
//! `FT_StreamRec` — a layout confirmation in its own right, since the
//! fields it writes are `size`, `pos`, `descriptor`, `pathname`, `read`
//! and `close` at exactly the offsets `ft/stream.rs` recovered.
//!
//! # Deviations
//!
//! The four firmware routines the opener stands on are not ported:
//!
//! - 0x082d3cb4, the open itself — `operator new(84)` followed by the
//!   file object's constructor at 0x08278dc4, then a check of the
//!   object's status word at +28: non-zero means the open failed, so the
//!   object is destroyed through vtable slot 1 and the out-parameter
//!   nulled.
//! - 0x082a5418, the length query, which locks a mutex and walks the
//!   object's directory entry.
//! - 0x082d3d7c / 0x082d3d40, the read and close callbacks, which go
//!   through 0x082787b8 (seek) and 0x082784b8 (read) and the object's
//!   virtual destructor.
//!
//! So the port takes them as an installable [`FtPlatformFileOps`], the
//! same shape `ft/trace.rs` uses for the unported logger: every entry is
//! one of the opener's own `bl` targets or stored literals, nothing about
//! the layer below is invented, and the opener's logic — which is what
//! was actually recovered — is reproduced exactly. With no ops installed
//! every open fails with [`FT_PLATFORM_OPEN_FAILED`], which is what the
//! hardware does when the volume is not mounted.

use crate::ft::stream::{FtStream, FtStreamCloseFunc, FtStreamIoFunc};

/// The opener's `moveq r0, #9` @ 0x082d3de4 — a null `FT_Stream`. These
/// two codes are the firmware's own numbering, not FreeType's;
/// [`ft_stream_open`](crate::ft::stream::ft_stream_open) only ever tests
/// them against zero.
pub const FT_PLATFORM_NULL_STREAM: i32 = 9;

/// The opener's `moveq r5, #20` @ 0x082d3e18 — the file layer refused,
/// leaving a null handle.
pub const FT_PLATFORM_OPEN_FAILED: i32 = 20;

/// The firmware file API [`ft_platform_stream_open`] is built on. Each
/// field names one address in the original opener.
#[derive(Clone, Copy)]
pub struct FtPlatformFileOps {
    /// 0x082d3cb4 — open `path` on `volume`, storing the file object in
    /// `*handle` (null when the open failed) and returning 1 on success.
    /// The opener ignores the return value and tests `*handle`.
    pub open: unsafe extern "C" fn(
        volume: i32,
        path: *const u8,
        handle: *mut *mut core::ffi::c_void,
    ) -> i32,
    /// 0x082a5418 — store the open file's length through `size`. Its
    /// return value is discarded by the opener.
    pub size: unsafe extern "C" fn(handle: *mut core::ffi::c_void, size: *mut u32) -> i32,
    /// 0x082d3d7c — the `FT_Stream_IoFunc` the opener plants in
    /// `stream->read`.
    pub read: FtStreamIoFunc,
    /// 0x082d3d40 — the `FT_Stream_CloseFunc` the opener plants in
    /// `stream->close`.
    pub close: FtStreamCloseFunc,
}

/// The installed file layer, or `None` for "no volume". ADDITION — the
/// original hard-codes the four addresses; see the module header.
static mut PLATFORM_FILE_OPS: Option<FtPlatformFileOps> = None;

/// Installs (or with `None` removes) the platform file layer, returning
/// the previous one. ADDITION — see the module header.
///
/// # Safety
/// Not re-entrant: no other thread may be inside
/// [`ft_platform_stream_open`] while the ops are swapped.
pub unsafe fn ft_set_platform_file_ops(
    ops: Option<FtPlatformFileOps>,
) -> Option<FtPlatformFileOps> {
    let slot = core::ptr::addr_of_mut!(PLATFORM_FILE_OPS);
    let previous = slot.read_volatile();
    slot.write_volatile(ops);
    previous
}

/// ft_platform_stream_open (the firmware's `FT_Stream_Open` body) —
/// original: `FUN_082d3ddc` @ 0x082d3ddc (120 bytes; 1 `bl` call site,
/// [`ft_stream_open`](crate::ft::stream::ft_stream_open) @ 0x0804f338).
///
/// Opens `pathname` and turns `stream` into a disk stream over it.
/// `pathname` is a volume-qualified path: byte 0 is a decimal digit read
/// as a *signed* char (`ldrb`, `- '0'`, `lsl #24`/`asr #24`) and used as
/// the volume index, byte 1 is a separator that is simply skipped, and
/// the path proper starts at byte 2. Both the volume digit and the
/// two-byte skip are unconditional — there is no format check, and
/// `pathname` itself is never null-tested.
///
/// On success the record gets `size` from the file layer, a zeroed
/// `pos`, the file object as `descriptor`, `pathname + 2` as `pathname`
/// (a pointer *into the caller's string*, not a copy) and the read/close
/// callbacks. `base` is deliberately left alone: a disk stream has no
/// image until [`ft_stream_enter_frame`](crate::ft::stream::ft_stream_enter_frame)
/// allocates one.
///
/// Failure leaves the record completely untouched — including on the
/// [`FT_PLATFORM_OPEN_FAILED`] path, which has already run the open.
///
/// # Safety
/// `stream` must be null or a valid `FtStream`; `pathname` must be a
/// NUL-terminated string of at least two bytes plus the path, and must
/// outlive the stream, which keeps a pointer into it.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_platform_stream_open(
    stream: *mut FtStream,
    pathname: *const u8,
) -> i32 {
    if stream.is_null() {
        return FT_PLATFORM_NULL_STREAM;
    }

    let Some(ops) = core::ptr::addr_of!(PLATFORM_FILE_OPS).read_volatile() else {
        return FT_PLATFORM_OPEN_FAILED;
    };

    let volume = (*pathname).wrapping_sub(b'0') as i8 as i32;
    let path = pathname.add(2);

    let mut handle: *mut core::ffi::c_void = core::ptr::null_mut();
    (ops.open)(volume, path, &mut handle);
    if handle.is_null() {
        return FT_PLATFORM_OPEN_FAILED;
    }

    (ops.size)(handle, &mut (*stream).size);
    (*stream).pathname = path as *mut core::ffi::c_void;
    (*stream).descriptor = handle;
    (*stream).pos = 0;
    (*stream).read = Some(ops.read);
    (*stream).close = Some(ops.close);
    0
}

#[cfg(test)]
extern crate std;

/// Serializes the tests that swap the global ops — including
/// `ft/stream.rs`'s, which drive `ft_stream_open` through them (see
/// PORTING.md's test-harness rule: one guard per `#[test]`, never
/// shadowed).
#[cfg(test)]
pub(crate) static TEST_OPS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::{string::String, vec::Vec};

    static mut OPEN_VOLUME: i32 = -99;
    static mut OPEN_PATH: [u8; 64] = [0; 64];
    static mut OPEN_CALLS: usize = 0;
    static mut OPEN_SUCCEEDS: bool = true;
    static mut SIZE_CALLS: usize = 0;
    /// The made-up file object the mock hands back.
    static mut FILE_OBJECT: u32 = 0;

    unsafe extern "C" fn mock_open(
        volume: i32,
        path: *const u8,
        handle: *mut *mut core::ffi::c_void,
    ) -> i32 {
        *core::ptr::addr_of_mut!(OPEN_VOLUME) = volume;
        *core::ptr::addr_of_mut!(OPEN_CALLS) += 1;
        let dst = core::ptr::addr_of_mut!(OPEN_PATH).cast::<u8>();
        let mut i = 0;
        while i < 63 && *path.add(i) != 0 {
            *dst.add(i) = *path.add(i);
            i += 1;
        }
        *dst.add(i) = 0;
        if *core::ptr::addr_of!(OPEN_SUCCEEDS) {
            *handle = core::ptr::addr_of_mut!(FILE_OBJECT).cast();
            1
        } else {
            *handle = core::ptr::null_mut();
            0
        }
    }

    unsafe extern "C" fn mock_size(_handle: *mut core::ffi::c_void, size: *mut u32) -> i32 {
        *core::ptr::addr_of_mut!(SIZE_CALLS) += 1;
        *size = 4242;
        0
    }

    unsafe extern "C" fn mock_read(
        _stream: *mut FtStream,
        _offset: u32,
        _buffer: *mut u8,
        _count: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn mock_close(_stream: *mut FtStream) {}

    unsafe fn install(succeeds: bool) -> FtPlatformFileOps {
        *core::ptr::addr_of_mut!(OPEN_CALLS) = 0;
        *core::ptr::addr_of_mut!(SIZE_CALLS) = 0;
        *core::ptr::addr_of_mut!(OPEN_VOLUME) = -99;
        *core::ptr::addr_of_mut!(OPEN_SUCCEEDS) = succeeds;
        let ops = FtPlatformFileOps {
            open: mock_open,
            size: mock_size,
            read: mock_read,
            close: mock_close,
        };
        ft_set_platform_file_ops(Some(ops));
        ops
    }

    unsafe fn opened_path() -> String {
        let bytes = core::ptr::addr_of!(OPEN_PATH).cast::<u8>();
        let mut out = Vec::new();
        let mut i = 0;
        while *bytes.add(i) != 0 {
            out.push(*bytes.add(i));
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn blank_stream() -> FtStream {
        FtStream {
            base: 7 as *mut u8,
            size: 0xdead,
            pos: 0xbeef,
            descriptor: core::ptr::null_mut(),
            pathname: core::ptr::null_mut(),
            read: None,
            close: None,
            memory: core::ptr::null_mut(),
            cursor: core::ptr::null_mut(),
            limit: core::ptr::null_mut(),
        }
    }

    #[test]
    fn open_splits_the_volume_digit_from_the_path_and_fills_the_record() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        let mut stream = blank_stream();
        let path = b"3:/Fonts/Helvetica.ttf\0";
        unsafe {
            let ops = install(true);
            assert_eq!(ft_platform_stream_open(&mut stream, path.as_ptr()), 0);
            assert_eq!(*core::ptr::addr_of!(OPEN_VOLUME), 3);
            assert_eq!(opened_path(), "/Fonts/Helvetica.ttf");
            assert_eq!(*core::ptr::addr_of!(SIZE_CALLS), 1);
            assert_eq!(stream.size, 4242);
            assert_eq!(stream.pos, 0);
            assert_eq!(stream.descriptor, core::ptr::addr_of_mut!(FILE_OBJECT).cast());
            // A pointer *into* the caller's string, two bytes in.
            assert_eq!(stream.pathname, path.as_ptr().add(2) as *mut core::ffi::c_void);
            assert_eq!(stream.read.map(|f| f as usize), Some(ops.read as usize));
            assert_eq!(stream.close.map(|f| f as usize), Some(ops.close as usize));
            // `base` is not part of the opener's job.
            assert_eq!(stream.base, 7 as *mut u8);
            ft_set_platform_file_ops(None);
        }
    }

    #[test]
    fn open_reads_the_volume_digit_as_a_signed_char() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        // `ldrb` then `- '0'` then sign-extend from 8 bits: the digits
        // give 0..9, and anything below '0' wraps to a negative volume
        // rather than a huge one.
        for (first, want) in [(b'0', 0i32), (b'9', 9), (b'/', -1), (0xffu8, 207 - 256)] {
            let mut stream = blank_stream();
            let path = [first, b':', b'x', 0];
            unsafe {
                install(true);
                assert_eq!(ft_platform_stream_open(&mut stream, path.as_ptr()), 0);
                assert_eq!(*core::ptr::addr_of!(OPEN_VOLUME), want, "first byte {first:#x}");
                ft_set_platform_file_ops(None);
            }
        }
    }

    #[test]
    fn a_null_stream_is_rejected_before_anything_is_opened() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        unsafe {
            install(true);
            assert_eq!(
                ft_platform_stream_open(core::ptr::null_mut(), b"0:/x\0".as_ptr()),
                FT_PLATFORM_NULL_STREAM
            );
            assert_eq!(*core::ptr::addr_of!(OPEN_CALLS), 0);
            ft_set_platform_file_ops(None);
        }
    }

    #[test]
    fn a_refused_open_leaves_the_record_untouched() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        let mut stream = blank_stream();
        unsafe {
            install(false);
            assert_eq!(
                ft_platform_stream_open(&mut stream, b"0:/missing\0".as_ptr()),
                FT_PLATFORM_OPEN_FAILED
            );
            assert_eq!(*core::ptr::addr_of!(OPEN_CALLS), 1);
            assert_eq!(*core::ptr::addr_of!(SIZE_CALLS), 0);
            assert_eq!((stream.size, stream.pos), (0xdead, 0xbeef));
            assert!(stream.read.is_none() && stream.close.is_none());
            ft_set_platform_file_ops(None);
        }
    }

    #[test]
    fn with_no_file_layer_installed_every_open_fails() {
        let _guard = TEST_OPS_LOCK.lock().unwrap();
        let mut stream = blank_stream();
        unsafe {
            assert!(ft_set_platform_file_ops(None).is_none());
            assert_eq!(
                ft_platform_stream_open(&mut stream, b"0:/x\0".as_ptr()),
                FT_PLATFORM_OPEN_FAILED
            );
            assert!(stream.read.is_none());
        }
    }
}

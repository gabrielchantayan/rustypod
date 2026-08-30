//! Big-endian u32 field reader over the stream-read core —
//! `stream_read_be32` @ 0x08057874.
//!
//! Original: `FUN_08057874` @ 0x08057874 (80 bytes; extent verified from the
//! raw words in osos.dec — the sibling u16 reader starts at 0x080578c4,
//! exactly where this function's `pop {r3, r4, r5, pc}` lands, so Ghidra's
//! 80-byte size is correct for once). 34 `bl` call sites, all unpredicated,
//! counted by decoding every B/BL word in osos.dec (callers rely on the
//! 0/1 result, not on a NULL guard).
//!
//! Algorithm: push {r3, r4, r5, lr} so the 4-byte read buffer lives at sp;
//! call the stream-read core @ 0x0805e754 with (ctx, sp, 4, NULL); if the
//! core returns nonzero, return 0 without touching `*out`. Otherwise gather
//! the four buffer bytes big-endian (`ldrb` x4, `lsl`/`orr` chain:
//! b0<<24 | b1<<16 | b2<<8 | b3), store to `*out`, return 1.
//!
//! The core @ 0x0805e754 (not yet ported) dereferences ctx twice — object
//! pointer, then vtable — and tail-calls vtable slot 4 (+0x10) with
//! (object, buf, len, mode=2); it returns 0 on success, -3 when the vfunc
//! reports a short/failed read of a nonzero length. Callers in the
//! 0x080570cc–0x08057874 cluster walk big-endian record bodies (tag
//! headers, offset tables) one u32 field per call; the u16 twin
//! `FUN_080578c4` is the same shape with len=2 and a `strh`.
//!
//! Deliberate deviations: the port assembles the word with
//! `u32::from_be_bytes` instead of four discrete `ldrb`+shift steps;
//! LLVM emits the same gather-and-reverse and the observable behaviour is
//! identical. The unported core is reached through the replaceable
//! [`STREAM_READ_CORE`] seam (ROM address on target, panic on host).

/// Observed ABI of the unported stream-read core at 0x0805e754:
/// `(ctx, buf, len, err_out) -> status`, status 0 on success.
pub type StreamReadCore = unsafe extern "C" fn(ctx: u32, buf: *mut u8, len: u32, err_out: *mut u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_stream_read_core(
    ctx: u32,
    buf: *mut u8,
    len: u32,
    err_out: *mut u32,
) -> i32 {
    let core: StreamReadCore = unsafe { core::mem::transmute(0x0805_e754usize) };
    unsafe { core(ctx, buf, len, err_out) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_stream_read_core(
    _ctx: u32,
    _buf: *mut u8,
    _len: u32,
    _err_out: *mut u32,
) -> i32 {
    panic!("stream_read_be32 requires stream-read core 0x0805e754")
}

#[cfg(target_os = "none")]
const DEFAULT_STREAM_READ_CORE: StreamReadCore = firmware_stream_read_core;
#[cfg(not(target_os = "none"))]
const DEFAULT_STREAM_READ_CORE: StreamReadCore = missing_stream_read_core;

/// The unported retailOS stream-read core @ 0x0805e754. Target builds call
/// the ROM entry directly; host tests replace this seam with a recorder.
pub static mut STREAM_READ_CORE: StreamReadCore = DEFAULT_STREAM_READ_CORE;

/// stream_read_be32 — original: `FUN_08057874` @ 0x08057874 (80 bytes;
/// 34 `bl` call sites, all unpredicated, counted by decoding every B/BL
/// word in osos.dec).
///
/// Reads four bytes from the stream context via the stream-read core and
/// stores them big-endian into `*out`. Returns 1 on success, 0 on core
/// failure; on failure `*out` is left untouched (the original branches
/// around the `str`).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_be32")]
pub unsafe extern "C" fn stream_read_be32(ctx: u32, out: *mut u32) -> i32 {
    let mut buf = [0u8; 4];
    let core = unsafe { core::ptr::addr_of_mut!(STREAM_READ_CORE).read_volatile() };
    if unsafe { core(ctx, buf.as_mut_ptr(), 4, core::ptr::null_mut()) } != 0 {
        return 0;
    }
    unsafe { *out = u32::from_be_bytes(buf) };
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static CORE_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut SEEN_CTX: u32 = 0;
    static mut SEEN_LEN: u32 = 0;
    static mut SEEN_ERR_OUT: usize = 0;
    static mut FILL: [u8; 4] = [0; 4];
    static mut STATUS: i32 = 0;

    unsafe extern "C" fn fake_stream_read_core(
        ctx: u32,
        buf: *mut u8,
        len: u32,
        err_out: *mut u32,
    ) -> i32 {
        unsafe {
            CALLS += 1;
            SEEN_CTX = ctx;
            SEEN_LEN = len;
            SEEN_ERR_OUT = err_out as usize;
            let fill = core::ptr::addr_of!(FILL).read();
            core::ptr::copy_nonoverlapping(fill.as_ptr(), buf, 4);
            core::ptr::addr_of!(STATUS).read()
        }
    }

    struct CoreReset;

    impl Drop for CoreReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STREAM_READ_CORE)
                    .write_volatile(DEFAULT_STREAM_READ_CORE);
            }
        }
    }

    fn install_core() {
        unsafe {
            core::ptr::addr_of_mut!(CALLS).write(0);
            core::ptr::addr_of_mut!(SEEN_CTX).write(0);
            core::ptr::addr_of_mut!(SEEN_LEN).write(0);
            core::ptr::addr_of_mut!(SEEN_ERR_OUT).write(usize::MAX);
            core::ptr::addr_of_mut!(STREAM_READ_CORE).write_volatile(fake_stream_read_core);
        }
    }

    #[test]
    fn reads_four_bytes_big_endian_and_reports_success() {
        let _lock = CORE_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        install_core();
        let _reset = CoreReset;
        unsafe {
            core::ptr::addr_of_mut!(FILL).write([0xde, 0xad, 0xbe, 0xef]);
            core::ptr::addr_of_mut!(STATUS).write(0);
        }

        let mut out: u32 = 0;
        let ok = unsafe { stream_read_be32(0x0801_2345, &mut out) };

        assert_eq!(ok, 1);
        assert_eq!(out, 0xdead_beef);
        assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 1);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEN_CTX).read() }, 0x0801_2345);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEN_LEN).read() }, 4);
        assert_eq!(unsafe { core::ptr::addr_of!(SEEN_ERR_OUT).read() }, 0);
    }

    #[test]
    fn every_byte_lane_lands_in_its_big_endian_slot() {
        let _lock = CORE_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        install_core();
        let _reset = CoreReset;
        unsafe { core::ptr::addr_of_mut!(STATUS).write(0) };

        let cases: [([u8; 4], u32); 4] = [
            ([1, 0, 0, 0], 0x0100_0000),
            ([0, 1, 0, 0], 0x0001_0000),
            ([0, 0, 1, 0], 0x0000_0100),
            ([0, 0, 0, 1], 0x0000_0001),
        ];
        for (bytes, want) in cases {
            unsafe { core::ptr::addr_of_mut!(FILL).write(bytes) };
            let mut out: u32 = 0;
            let ok = unsafe { stream_read_be32(0, &mut out) };
            assert_eq!(ok, 1);
            assert_eq!(out, want, "bytes {bytes:02x?}");
        }
    }

    #[test]
    fn core_failure_returns_zero_and_leaves_out_untouched() {
        let _lock = CORE_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        install_core();
        let _reset = CoreReset;
        unsafe {
            core::ptr::addr_of_mut!(FILL).write([0xaa, 0xbb, 0xcc, 0xdd]);
            core::ptr::addr_of_mut!(STATUS).write(-3);
        }

        let mut out: u32 = 0x5afe_5afe;
        let ok = unsafe { stream_read_be32(0xfeed, &mut out) };

        assert_eq!(ok, 0);
        assert_eq!(out, 0x5afe_5afe);
        assert_eq!(unsafe { core::ptr::addr_of!(CALLS).read() }, 1);
    }
}

//! Output-stream sentry cleanup — `FUN_083d8428` @ **0x083d8428**.
//!
//! True extent: 64 bytes through exclusive end 0x083d8468, comprising 60
//! executable bytes and the synchronization-byte pointer at 0x083d8464.
//! Raw A32 words verify zero plain and one predicated outgoing BL (BLNE at
//! 0x083d8458 to 0x083d6ec4); inbound: one plain BL at 0x083b5408, no
//! predicated BLs. The next real function starts with PUSH at 0x083d8468.
//!
//! Load the stream from the sentry's first target-width word, apply the
//! signed vtable adjustment at -12, and inspect basic_ios flags at +4.
//! Unless bit 0x2000 is set, read the synchronization byte at 0x08a0fbc8;
//! when nonzero, classify the stream with secondary_standard_stream_subobject.
//! Discard that result and return the original sentry, without flushing.
//!
//! Deviations: host-only operations replace the firmware global and helper
//! to exercise conditional access without firmware RAM. Target builds call
//! the existing Rust port directly. All object fields remain 32-bit words.

#[cfg(not(target_os = "none"))]
pub(crate) struct HostOps {
    pub(crate) synchronized: unsafe fn() -> bool,
    pub(crate) secondary: unsafe fn(*mut u32) -> u32,
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps {
    synchronized: || panic!("firmware stream synchronization unavailable"),
    secondary: |_| panic!("firmware secondary context unavailable"),
};

/// # Safety
/// `sentry` contains a valid target-width stream pointer. Its vtable has a
/// readable signed adjustment at -12, and the adjusted flags word is valid.
/// When synchronization is enabled, the stream must also satisfy the
/// secondary-standard-stream helper's requirements. No validation is added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ostream_sentry_cleanup(sentry: *mut u32) -> *mut u32 {
    let stream = sentry.read() as usize as *mut u32;
    let vtable = stream.read() as usize as *const i32;
    let adjustment = vtable.sub(3).read();
    let owner = stream.cast::<u8>().wrapping_offset(adjustment as isize).cast::<u32>();
    if owner.add(1).read_volatile() & 0x2000 == 0 {
        #[cfg(target_os = "none")]
        let synchronized = (0x08a0fbc8 as *const u8).read_volatile() != 0;
        #[cfg(not(target_os = "none"))]
        let synchronized = (HOST_OPS.synchronized)();
        if synchronized {
            #[cfg(target_os = "none")]
            let _ = super::secondary_standard_stream_subobject::secondary_standard_stream_subobject(stream.cast());
            #[cfg(not(target_os = "none"))]
            let _ = (HOST_OPS.secondary)(stream);
        }
    }
    sentry
}

#[cfg(test)]
mod tests {
    use super::*;
    static mut SYNC_BYTE: u8 = 0;
    static mut SYNC_READS: u32 = 0;
    static mut CLASSIFICATIONS: u32 = 0;
    unsafe fn synchronized() -> bool {
        SYNC_READS += 1;
        SYNC_BYTE != 0
    }
    unsafe fn secondary(_: *mut u32) -> u32 {
        CLASSIFICATIONS += 1;
        // The return value must not become the cleanup return value.
        0xffff_ffff
    }

    #[test]
    fn signed_adjustments_flag_short_circuit_and_nonboolean_sync_byte() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OSTREAM_SENTRY_CLEANUP, 4096,
        ) else { return; };
        unsafe {
            let saved = core::ptr::read(core::ptr::addr_of!(HOST_OPS));
            HOST_OPS = HostOps { synchronized, secondary };
            let prefix = slab.cast::<i32>();
            let stream = slab.add(128).cast::<u32>();
            let sentry = slab.add(256).cast::<u32>();
            stream.write(prefix.add(3) as usize as u32);
            sentry.write(stream as usize as u32);
            sentry.add(1).write(0xa5a5_a5a5);
            for adjustment in [-32, 0, 32] {
                prefix.write(adjustment);
                let owner = stream.cast::<u8>().offset(adjustment as isize).cast::<u32>();
                for flags in [0, 1, 0x2000, 0x2001, 0xffff_dfff, 0xffff_ffff] {
                    owner.add(1).write(flags);
                    for byte in [0, 1, 0x80, 0xff] {
                        SYNC_BYTE = byte;
                        SYNC_READS = 0;
                        CLASSIFICATIONS = 0;
                        assert_eq!(ostream_sentry_cleanup(sentry), sentry);
                        assert_eq!(SYNC_READS, u32::from(flags & 0x2000 == 0));
                        assert_eq!(CLASSIFICATIONS, u32::from(flags & 0x2000 == 0 && byte != 0));
                        assert_eq!(owner.add(1).read(), flags);
                        assert_eq!(sentry.add(1).read(), 0xa5a5_a5a5);
                    }
                }
            }
            core::ptr::write(core::ptr::addr_of_mut!(HOST_OPS), saved);
        }
    }
}

//! Poll cached member payloads — FUN_081ff128 @ 0x081ff128.
//! True extent: 316 bytes (0x081ff128..0x081ff264), including the three
//! literals at 0x081ff258; executable body is 304 bytes. Raw aligned A32
//! decoding finds two inbound plain BLs (0x081fdf68, 0x081fdfa0), no
//! predicated inbound BLs; outgoing four plain BLs, one BLNE, one BLX.
//!
//! Seed the change mask from the active channel's pending mask. Poll 17
//! ARM C++ member pointers, initializing each output's length to 1 and its
//! index to the slot. Skip slot 9 on non-300th ticks once initialized.
//! Successful callbacks must report the cached length plus one; compare and
//! copy changed payloads, OR their bits, then dispatch a nonzero mask and
//! return the dispatcher status (otherwise zero).
//!
//! Deliberate deviations: host pointer-bearing records use native-width
//! pointers with repr(C), rather than target byte offsets. The 24-byte output
//! buffer is zero-initialized instead of leaving payload bytes indeterminate;
//! valid callbacks fill every reported payload byte. Unsigned remainder uses
//! Rust arithmetic instead of the ADS quotient/remainder ABI. The unported
//! mask dispatcher remains an exact-address target seam, not a guessed port.

use core::ptr::{addr_of, read_volatile};

const SLOT_COUNT: usize = 17;
type Query = unsafe extern "C" fn(*mut u8, *mut u8) -> u32;
type Dispatch = unsafe extern "C" fn(*mut u8, u32) -> u32;

/// ARM C++ member pointer: code address (or vtable byte offset) and a
/// signed `this` adjustment shifted left once, with virtual-dispatch bit 0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PayloadMember {
    pub entry: usize,
    pub adjustment_and_virtual: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CachedPayload {
    pub unresolved: u32,
    pub bytes: *mut u8,
    pub length: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
pub struct PayloadCacheState {
    pub flags: [u8; 4],
    pub active_channel: u32,
    pub unresolved: [u8; 20],
    pub payloads: [CachedPayload; SLOT_COUNT],
}

/// Host bindings replace only firmware globals and the unported dispatcher.
/// Target records remain at their original retailOS addresses.
#[derive(Clone, Copy)]
pub struct PayloadPollBindings {
    pub state: *mut PayloadCacheState,
    pub channel_masks: *const u32,
    pub members: *const PayloadMember,
    pub dispatch: Dispatch,
}

#[cfg(not(target_os = "none"))]
pub static mut PAYLOAD_POLL_BINDINGS: Option<PayloadPollBindings> = None;

#[cfg(target_os = "none")]
unsafe fn bindings() -> PayloadPollBindings {
    PayloadPollBindings {
        state: 0x089cca68 as *mut PayloadCacheState,
        channel_masks: 0x08ac8d74 as *const u32,
        members: 0x08ac8ca4 as *const PayloadMember,
        // Raw 0x081ff034 consumes r1's mask and returns the final send status
        // in r0. Its incoming r0 is unused, but retail forwards this anyway.
        dispatch: core::mem::transmute(0x081ff034usize),
    }
}

#[cfg(not(target_os = "none"))]
unsafe fn bindings() -> PayloadPollBindings {
    read_volatile(addr_of!(PAYLOAD_POLL_BINDINGS)).expect("payload polling requires host bindings")
}

#[inline(always)]
unsafe fn poll(this: *mut u8, bindings: PayloadPollBindings) -> u32 {
    let state = bindings.state;
    let channel = read_volatile(addr_of!((*state).active_channel)) as usize;
    let mut changed = read_volatile(bindings.channel_masks.add(channel + 3));
    let mut output = [0u8; 24];
    for index in 0..SLOT_COUNT {
        let member = read_volatile(bindings.members.add(index));
        output[0] = 1;
        output[1] = index as u8;
        if index == 9 && read_volatile(this.add(0x2d0).cast::<u32>()) % 300 != 0
            && read_volatile(addr_of!((*state).flags[3])) != 0 {
            continue;
        }
        let adjusted = this.offset((member.adjustment_and_virtual >> 1) as isize);
        let entry = if member.adjustment_and_virtual & 1 != 0 {
            let vtable = read_volatile(adjusted.cast::<*const u8>());
            read_volatile(vtable.add(member.entry & !3).cast::<usize>())
        } else {
            member.entry
        };
        let query: Query = core::mem::transmute(entry);
        if query(adjusted, output.as_mut_ptr()) != 0 {
            continue;
        }
        let cached = addr_of!((*state).payloads[index]);
        let length = read_volatile(addr_of!((*cached).length)) as usize;
        if (output[0] as u32).wrapping_sub(1) != length as u32 {
            crate::heap::veneers::heap_panic();
        }
        let bytes = read_volatile(addr_of!((*cached).bytes));
        if crate::libc::memcmp::memcmp(bytes, output.as_ptr().add(2), length) != 0 {
            // Reload after comparison, matching the target's loads.
            let length = read_volatile(addr_of!((*cached).length)) as usize;
            let bytes = read_volatile(addr_of!((*cached).bytes));
            crate::libc::rt_memcpy::__rt_memcpy(bytes, output.as_ptr().add(2), length);
            changed |= 1u32 << index;
        }
    }
    if changed == 0 { 0 } else { (bindings.dispatch)(this, changed) }
}

/// # Safety
/// Bindings must refer to valid firmware-shaped records, active_channel must
/// select a readable pending mask, and this+0x2d0 must hold an aligned tick.
/// Each member must be callable with its decoded adjustment/vtable offset.
/// Successful callbacks initialize their entire payload (at most 22 bytes),
/// reporting cached length+1. Cached buffers must be writable for that length.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn member_payload_cache_poll(this: *mut u8) -> u32 {
    poll(this, bindings())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        padding: [u32; 180],
        ticks: u32,
    }

    unsafe extern "C" fn query(_: *mut u8, output: *mut u8) -> u32 {
        let index = *output.add(1);
        // Failed callbacks must not modify their cache or contribute a bit.
        if index == 4 { return 7; }
        *output = if index == 0 { 1 } else { 3 };
        *output.add(2) = index;
        *output.add(3) = index.wrapping_add(1);
        0
    }

    unsafe extern "C" fn dispatch(_: *mut u8, mask: u32) -> u32 { mask ^ 0x8000_0000 }

    #[test]
    fn changes_pending_bits_failures_zero_length_and_throttle() {
        unsafe {
            let mut object = [0u32; 181];
            let mut bytes = [[0xa5u8; 2]; SLOT_COUNT];
            let mut state = PayloadCacheState {
                flags: [0; 4], active_channel: 1, unresolved: [0; 20],
                payloads: core::array::from_fn(|i| CachedPayload {
                    unresolved: 0, bytes: bytes[i].as_mut_ptr(),
                    length: if i == 0 { 0 } else { 2 }, reserved: [0; 3],
                }),
            };
            let members = [PayloadMember { entry: query as *const () as usize,
                adjustment_and_virtual: 0 }; SLOT_COUNT];
            let masks = [0, 0, 0, 0, 1 << 23, 0];
            let bindings = PayloadPollBindings { state: &mut state,
                channel_masks: masks.as_ptr(), members: members.as_ptr(), dispatch };
            object[180] = 1;
            let expected = ((1u32 << 17) - 1) & !((1 << 0) | (1 << 4));
            assert_eq!(poll(object.as_mut_ptr().cast(), bindings),
                (expected | (1 << 23)) ^ 0x8000_0000);
            for i in 0..SLOT_COUNT {
                assert_eq!(bytes[i], if i == 0 || i == 4 { [0xa5; 2] }
                    else { [i as u8, i as u8 + 1] });
            }
            state.flags[3] = 1;
            bytes[9] = [0xa5; 2];
            assert_eq!(poll(object.as_mut_ptr().cast(), bindings), (1 << 23) ^ 0x8000_0000);
            assert_eq!(bytes[9], [0xa5; 2]);
            object[180] = 300;
            assert_eq!(poll(object.as_mut_ptr().cast(), bindings),
                ((1 << 23) | (1 << 9)) ^ 0x8000_0000);
            assert_eq!(bytes[9], [9, 10]);
            state.active_channel = 0;
            assert_eq!(poll(object.as_mut_ptr().cast(), bindings), 0);
        }
    }

    #[test]
    fn signed_adjustment_and_virtual_offset_select_real_member() {
        unsafe {
            let vtable = [query as *const () as usize; 2];
            let mut object = Object { vtable: vtable.as_ptr(), padding: [0; 180], ticks: 0 };
            let base = (&mut object as *mut Object).cast::<u8>();
            let this = base.add(4);
            this.add(0x2d0).cast::<u32>().write(0);
            let mut bytes = [[0xa5u8; 2]; SLOT_COUNT];
            let mut state = PayloadCacheState {
                flags: [0; 4], active_channel: 0, unresolved: [0; 20],
                payloads: core::array::from_fn(|i| CachedPayload {
                    unresolved: 0, bytes: bytes[i].as_mut_ptr(),
                    length: if i == 0 { 0 } else { 2 }, reserved: [0; 3],
                }),
            };
            let members = [PayloadMember { entry: core::mem::size_of::<usize>(),
                adjustment_and_virtual: (-4i32 << 1) | 1 }; SLOT_COUNT];
            let bindings = PayloadPollBindings { state: &mut state,
                channel_masks: [0u32; 6].as_ptr(), members: members.as_ptr(), dispatch };
            let expected = ((1u32 << 17) - 1) & !((1 << 0) | (1 << 4));
            assert_eq!(poll(this, bindings), expected ^ 0x8000_0000);
            assert_eq!(bytes[16], [16, 17]);
        }
    }
}

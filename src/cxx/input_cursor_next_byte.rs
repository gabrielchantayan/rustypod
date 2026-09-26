//! Reads the next byte from an input cursor — `FUN_083da654` @ `0x083da654`.
//!
//! Raw `osos.dec` establishes the exact 76-byte extent from `push {r3,lr}` at
//! `0x083da654` through `pop {ip,pc}` at `0x083da69c`; the standalone `bx lr`
//! at `0x083da6a0` and `push {r4-r8,lr}` at `0x083da6a4` begin separately
//! entered functions. The body has no direct plain or predicated `bl`; it has
//! one indirect `blx` through vtable slot `+0x24`. Complete A32 decoding finds
//! one inbound plain `bl` at `0x083d82d4` and one predicated `blne` at
//! `0x083daf60`.
//!
//! Algorithm: when cursor flag bit two is set and `current` has not reached
//! `end`, return `*current` and advance `current` by one. Otherwise invoke the
//! cursor object's vtable slot `+0x24` and return its result. Deliberate
//! deviation: host cursor and vtable fields are widened so host pointers and
//! function addresses are not truncated; target builds use the retail 32-bit
//! layout and volatile accesses.

const HAS_BUFFERED_BYTE: u32 = 4;
const CURRENT_OFFSET_WORD: usize = 6;
const END_OFFSET_WORD: usize = 7;
const NEXT_BYTE_SLOT_WORD: usize = 9;

#[cfg(target_os = "none")]
#[repr(C)]
pub struct InputByteCursor {
    pub vtable: u32,
    pub flags: u32,
    pub unresolved_08_to_14: [u32; 4],
    pub current: u32,
    pub end: u32,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct InputByteCursor {
    pub vtable: *const HostInputByteCursorVtable,
    pub flags: u32,
    pub current: *mut u8,
    pub end: *mut u8,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostInputByteCursorVtable {
    pub unresolved_00_to_20: [usize; 9],
    pub next_byte: unsafe extern "C" fn(*mut InputByteCursor) -> u32,
}

/// Returns the next buffered byte, or delegates exhaustion to vtable slot
/// `+0x24`.
///
/// # Safety
///
/// `cursor` must be valid. With flag bit two set and unequal `current`/`end`,
/// `current` must be readable; otherwise its vtable slot `+0x24` must be
/// callable. The stock routine does not check either condition.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_cursor_next_byte(cursor: *mut InputByteCursor) -> u32 {
    #[cfg(target_os = "none")]
    {
        let flags = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*cursor).flags)) };
        if flags & HAS_BUFFERED_BYTE != 0 {
            let current = unsafe { core::ptr::read_volatile((cursor as *mut u32).add(CURRENT_OFFSET_WORD)) };
            let end = unsafe { core::ptr::read_volatile((cursor as *mut u32).add(END_OFFSET_WORD)) };
            if current != end {
                let byte = unsafe { core::ptr::read_volatile(current as *const u8) };
                unsafe { core::ptr::write_volatile((cursor as *mut u32).add(CURRENT_OFFSET_WORD), current.wrapping_add(1)) };
                return byte as u32;
            }
        }
        let vtable = unsafe { core::ptr::read_volatile(cursor.cast::<u32>()) };
        let address = unsafe { core::ptr::read_volatile((vtable as *const u32).add(NEXT_BYTE_SLOT_WORD)) };
        let next_byte: unsafe extern "C" fn(*mut InputByteCursor) -> u32 = unsafe { core::mem::transmute(address as usize) };
        unsafe { next_byte(cursor) }
    }

    #[cfg(not(target_os = "none"))]
    {
        let flags = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*cursor).flags)) };
        if flags & HAS_BUFFERED_BYTE != 0 {
            let current = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*cursor).current)) };
            let end = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*cursor).end)) };
            if current != end {
                let byte = unsafe { core::ptr::read_volatile(current) };
                unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*cursor).current), current.add(1)) };
                return byte as u32;
            }
        }
        let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*cursor).vtable)) };
        unsafe { ((*vtable).next_byte)(cursor) }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static CURSOR_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCHES: u32 = 0;
    static mut DISPATCH_CURSOR: *mut InputByteCursor = core::ptr::null_mut();

    unsafe extern "C" fn record_next_byte(cursor: *mut InputByteCursor) -> u32 {
        unsafe {
            DISPATCHES += 1;
            DISPATCH_CURSOR = cursor;
        }
        0xface
    }

    fn reset_dispatch() {
        unsafe {
            DISPATCHES = 0;
            DISPATCH_CURSOR = core::ptr::null_mut();
        }
    }

    fn vtable() -> HostInputByteCursorVtable {
        HostInputByteCursorVtable { unresolved_00_to_20: [0; 9], next_byte: record_next_byte }
    }

    #[test]
    fn returns_buffered_byte_and_advances_only_one_byte() {
        let _guard = CURSOR_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_dispatch();
        let vtable = vtable();
        let mut bytes = [0x23, 0xa5];
        let mut cursor = InputByteCursor {
            vtable: &vtable,
            flags: HAS_BUFFERED_BYTE,
            current: bytes.as_mut_ptr(),
            end: unsafe { bytes.as_mut_ptr().add(2) },
        };

        assert_eq!(unsafe { input_cursor_next_byte(&mut cursor) }, 0x23);
        assert_eq!(cursor.current, unsafe { bytes.as_mut_ptr().add(1) });
        assert_eq!(unsafe { DISPATCHES }, 0);
    }

    #[test]
    fn dispatches_when_buffering_is_disabled() {
        let _guard = CURSOR_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_dispatch();
        let vtable = vtable();
        let mut bytes = [0x23];
        let mut cursor = InputByteCursor {
            vtable: &vtable,
            flags: 0,
            current: bytes.as_mut_ptr(),
            end: unsafe { bytes.as_mut_ptr().add(1) },
        };

        assert_eq!(unsafe { input_cursor_next_byte(&mut cursor) }, 0xface);
        assert_eq!(cursor.current, bytes.as_mut_ptr());
        assert_eq!(unsafe { DISPATCHES }, 1);
        assert!(core::ptr::eq(unsafe { DISPATCH_CURSOR }, &mut cursor));
    }

    #[test]
    fn dispatches_at_buffer_end_even_when_buffering_is_enabled() {
        let _guard = CURSOR_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_dispatch();
        let vtable = vtable();
        let mut bytes = [0x23];
        let end = unsafe { bytes.as_mut_ptr().add(1) };
        let mut cursor = InputByteCursor {
            vtable: &vtable,
            flags: HAS_BUFFERED_BYTE,
            current: end,
            end,
        };

        assert_eq!(unsafe { input_cursor_next_byte(&mut cursor) }, 0xface);
        assert_eq!(cursor.current, end);
        assert_eq!(unsafe { DISPATCHES }, 1);
    }
}

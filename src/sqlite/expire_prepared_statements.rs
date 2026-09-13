//! Mark every prepared statement on a connection as expired.
//!
//! `sqlite3_expire_prepared_statements` — original `FUN_083767ec` at load
//! address `0x083767ec`, 28 bytes. Raw ARM extent is
//! `0x083767ec..0x08376808`: the final `bx lr` is at `0x08376804`, followed
//! by a separately linked function. Every ARM immediate branch in `osos.dec`
//! was decoded: **6 direct `bl` callers**, all unconditional, at
//! `0x082c52b0`, `0x08373c24`, `0x08382544`, `0x08388b28`, `0x08388bbc`, and
//! `0x083912c4`; there are no predicated or tail-branch callers.
//!
//! The routine walks `Connection.p_vdbe` through `Vdbe.p_next` and stores one
//! to each statement's `expired` byte. It deliberately retains the original's
//! absent NULL guard: `connection` must name a live connection. Named
//! `#[repr(C)]` fields replace target byte offsets so 64-bit host pointers
//! cannot overlap.

use super::vdbe::Vdbe;

/// The slice of SQLite's connection object needed by this routine.
#[repr(C)]
pub struct Connection {
    /// +0x00..+0x8c: unmodeled connection state.
    pub _gap_00: [u8; 0x8c],
    /// +0x8c: first live prepared statement (`pVdbe`).
    pub p_vdbe: *mut Vdbe,
}

#[cfg(target_pointer_width = "32")]
const _CONNECTION_P_VDBE_OFFSET: [u8; 0x8c] = [0; core::mem::offset_of!(Connection, p_vdbe)];

/// Set `expired` on every statement registered with `connection`.
///
/// # Safety
/// `connection` must be a valid writable [`Connection`], and every linked
/// [`Vdbe`] must be valid and writable until its null `p_next` terminator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_expire_prepared_statements(connection: *mut Connection) {
    let mut statement = (*connection).p_vdbe;
    while !statement.is_null() {
        (*statement).expired = 1;
        statement = (*statement).p_next;
    }
}

#[cfg(test)]
mod tests {
    use super::{sqlite3_expire_prepared_statements, Connection};
    use crate::sqlite::vdbe::Vdbe;
    use core::mem::MaybeUninit;

    unsafe fn blank_statement() -> Vdbe {
        MaybeUninit::<Vdbe>::zeroed().assume_init()
    }

    #[test]
    fn expires_every_statement_in_list_order() {
        unsafe {
            let mut first = blank_statement();
            let mut second = blank_statement();
            let mut third = blank_statement();
            first.expired = 0;
            second.expired = 0xa5;
            third.expired = 0;
            first.p_next = &mut second;
            second.p_next = &mut third;

            let mut connection = MaybeUninit::<Connection>::zeroed().assume_init();
            connection.p_vdbe = &mut first;

            sqlite3_expire_prepared_statements(&mut connection);

            assert_eq!((first.expired, second.expired, third.expired), (1, 1, 1));
            assert!(third.p_next.is_null(), "the terminating link remains null");
        }
    }

    #[test]
    fn empty_list_leaves_unlinked_statement_untouched() {
        unsafe {
            let mut unlinked = blank_statement();
            unlinked.expired = 0xa5;
            let mut connection = MaybeUninit::<Connection>::zeroed().assume_init();

            sqlite3_expire_prepared_statements(&mut connection);

            assert_eq!(unlinked.expired, 0xa5);
        }
    }
}

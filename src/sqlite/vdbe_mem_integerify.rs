//! INTEGER-ifying a VDBE value cell — `sqlite3VdbeMemIntegerify` from the
//! retailOS SQLite 3.5.x cluster.
//!
//! `FUN_0838bf50` at load address **0x0838bf50** is 40 bytes:
//! 0x0838bf50..0x0838bf78. The next word at 0x0838bf78 is the separate
//! `stmdb` entry of `sqlite3VdbeMemSetNull`; there is no literal pool.
//! Decoding every ARM B/BL word in `osos.dec` found **10 unconditional `bl`
//! call sites** (0x08387bf0, 0x08387ddc, 0x0838805c, 0x08388090, 0x08388ab8,
//! 0x08388c38, 0x0838927c, 0x0838952c, 0x0838a570, and 0x0838a578), with no
//! predicated entries.
//!
//! The function obtains `sqlite3VdbeIntValue(p_mem)`, writes the resulting
//! signed 64-bit integer to `Mem.u`, replaces only the low five SQLite type
//! bits of `Mem.flags` with `MEM_Int`, and returns `SQLITE_OK`. Attribute bits
//! and all unrelated fields survive. The typed `repr(C)` [`Mem`] fields replace
//! the original +0x00/+0x1c accesses so host pointer widths cannot overlap
//! fields. The callee `vdbe_int_value` at 0x0838b5c4 is already ported and is
//! called directly; no dispatch seam is added.

use super::vdbe::Mem;
use super::vdbe_int_value::vdbe_int_value;
use super::vdbe_mem_set_int64::MEM_INT;
use super::vdbe_mem_set_null::MEM_TYPE_BITS;
use super::vdbe_mem_realify::SQLITE_OK;

/// vdbe_mem_integerify — original: `FUN_0838bf50` @ 0x0838bf50 (40 bytes;
/// 10 unconditional `bl` call sites).
///
/// `sqlite3VdbeMemIntegerify`: project `p_mem` to an `i64`, put that value in
/// its integer arm, replace only the five type bits with `MEM_Int`, and return
/// `SQLITE_OK`. The flags are deliberately reloaded after `vdbe_int_value`,
/// preserving any flag side effects from that helper.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_integerify(p_mem: *mut Mem) -> i32 {
    (*p_mem).u = vdbe_int_value(p_mem) as u64;
    (*p_mem).flags = ((*p_mem).flags & !MEM_TYPE_BITS) | MEM_INT;
    SQLITE_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem(value: i64, flags: u16) -> Mem {
        Mem {
            u: value as u64,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x0bad_1000usize as *mut u8,
            z: 0x0bad_2000usize as *mut u8,
            n: -123_456_789,
            flags,
            value_type: 0xa5,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc: 0x0bad_4000usize as *mut u8,
        }
    }

    #[test]
    fn integer_values_survive_the_projection_bit_for_bit() {
        let values = [
            0i64,
            1,
            -1,
            0x7fff_ffff,
            -0x8000_0000,
            0x1_0000_0000,
            -0x1_0000_0000,
            i64::MIN,
            i64::MAX,
            0xdead_beef_cafe_f00du64 as i64,
        ];

        for value in values {
            let mut p_mem = mem(value, MEM_INT);
            assert_eq!(unsafe { vdbe_mem_integerify(&mut p_mem) }, SQLITE_OK);
            assert_eq!(p_mem.u, value as u64, "value={value:#x}");
        }
    }

    #[test]
    fn all_type_bit_combinations_become_mem_int_and_attributes_survive() {
        // MEM_Int gives vdbe_int_value a self-contained projection path. It
        // wins over every other low type bit, leaving this test exhaustive
        // over the wrapper's read-modify-write input states.
        for type_bits in 0..=MEM_TYPE_BITS {
            let original_flags = 0xbe00 | type_bits | MEM_INT;
            let mut p_mem = mem(-99, original_flags);
            unsafe { vdbe_mem_integerify(&mut p_mem) };
            assert_eq!(
                p_mem.flags,
                (original_flags & !MEM_TYPE_BITS) | MEM_INT,
                "flags={original_flags:#06x}",
            );
        }
    }

    #[test]
    fn conversion_leaves_all_non_integer_non_flag_fields_untouched() {
        let mut p_mem = mem(42, 0x7fe0 | MEM_INT | 0x0002);
        let before = mem(42, 0x7fe0 | MEM_INT | 0x0002);

        unsafe { vdbe_mem_integerify(&mut p_mem) };

        assert_eq!(p_mem.r.to_bits(), before.r.to_bits());
        assert_eq!(p_mem.db, before.db);
        assert_eq!(p_mem.z, before.z);
        assert_eq!(p_mem.n, before.n);
        assert_eq!(p_mem.value_type, before.value_type);
        assert_eq!(p_mem.enc, before.enc);
        assert_eq!(p_mem.x_del, before.x_del);
        assert_eq!(p_mem.z_malloc, before.z_malloc);
    }
}

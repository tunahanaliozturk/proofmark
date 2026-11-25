//! Checksums and encodings S3 uses: CRC32, CRC32C, CRC64NVME, SHA-256, MD5,
//! lowercase hex and padded base64.
//!
//! The CRCs are table-driven and written here rather than taken from a crate:
//! all three are reflected CRCs that differ only in polynomial and width, and
//! the tests pin each one to the check value in the CRC catalogue.

/// Reflected CRC-32 polynomial (`CRC_32_ISO_HDLC`, poly 0x04c11db7).
const CRC32_REFLECTED: u32 = 0xedb8_8320;
/// Reflected CRC-32C polynomial (`CRC_32_ISCSI`, poly 0x1edc6f41).
const CRC32C_REFLECTED: u32 = 0x82f6_3b78;
/// Reflected CRC-64/NVME polynomial (`CRC_64_NVME`, poly 0xad93d23594c93659).
const CRC64NVME_REFLECTED: u64 = 0x9a6c_9329_ac4b_c9b5;

const CRC32_TABLE: [u32; 256] = table32(CRC32_REFLECTED);
const CRC32C_TABLE: [u32; 256] = table32(CRC32C_REFLECTED);
const CRC64NVME_TABLE: [u64; 256] = table64(CRC64NVME_REFLECTED);

const fn table32(poly: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0usize;
    let mut value = 0u32;
    while index < 256 {
        let mut crc = value;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ poly
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
        value += 1;
    }
    table
}

const fn table64(poly: u64) -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut index = 0usize;
    let mut value = 0u64;
    while index < 256 {
        let mut crc = value;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ poly
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
        value += 1;
    }
    table
}

fn reflected32(table: &[u32; 256], data: &[u8]) -> u32 {
    let crc = data.iter().fold(u32::MAX, |crc, &byte| {
        table[usize::from(crc.to_le_bytes()[0] ^ byte)] ^ (crc >> 8)
    });
    !crc
}

/// CRC-32 as S3 uses it for `x-amz-checksum-crc32` (`CRC_32_ISO_HDLC`).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    reflected32(&CRC32_TABLE, data)
}

/// CRC-32C as S3 uses it for `x-amz-checksum-crc32c` (`CRC_32_ISCSI`).
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    reflected32(&CRC32C_TABLE, data)
}

/// CRC-64/NVME as S3 uses it for `x-amz-checksum-crc64nvme` (`CRC_64_NVME`).
#[must_use]
pub fn crc64nvme(data: &[u8]) -> u64 {
    let crc = data.iter().fold(u64::MAX, |crc, &byte| {
        CRC64NVME_TABLE[usize::from(crc.to_le_bytes()[0] ^ byte)] ^ (crc >> 8)
    });
    !crc
}

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Lowercase hex of the SHA-256 of `data`, the form SigV4 uses everywhere.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

const MD5_SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_CONSTANTS: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

fn md5_block(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut words = [0u32; 16];
    for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    let [mut a, mut b, mut c, mut d] = *state;
    for round in 0..64 {
        let (mix, index) = match round / 16 {
            0 => ((b & c) | (!b & d), round),
            1 => ((d & b) | (!d & c), (5 * round + 1) % 16),
            2 => (b ^ c ^ d, (3 * round + 5) % 16),
            _ => (c ^ (b | !d), (7 * round) % 16),
        };
        let sum = mix
            .wrapping_add(a)
            .wrapping_add(MD5_CONSTANTS[round])
            .wrapping_add(words[index]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(sum.rotate_left(MD5_SHIFTS[round]));
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// MD5 of `data` (RFC 1321), for `Content-MD5` and single-part `ETag` values.
///
/// MD5 is broken as a cryptographic hash. S3 uses it as a checksum, and so
/// does proofmark.
#[must_use]
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut state = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let (blocks, rest) = data.as_chunks::<64>();
    for block in blocks {
        md5_block(&mut state, block);
    }
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let tail_len = if rest.len() < 56 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8);
    tail[tail_len - 8..tail_len].copy_from_slice(&bits.to_le_bytes());
    for block in tail[..tail_len].as_chunks::<64>().0 {
        md5_block(&mut state, block);
    }
    let mut out = [0u8; 16];
    for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *bytes = word.to_le_bytes();
    }
    out
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Standard base64 with padding (RFC 4648 section 4), the encoding S3 uses
/// for `Content-MD5` and `x-amz-checksum-*` values.
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let b0 = group[0];
        let b1 = group.get(1).copied().unwrap_or(0);
        let b2 = group.get(2).copied().unwrap_or(0);
        let sextets = [
            b0 >> 2,
            ((b0 & 0x03) << 4) | (b1 >> 4),
            ((b1 & 0x0f) << 2) | (b2 >> 6),
            b2 & 0x3f,
        ];
        for (position, sextet) in sextets.iter().enumerate() {
            if position <= group.len() {
                out.push(char::from(ALPHABET[usize::from(*sextet)]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Check values for the input "123456789", from crc-catalog 2.5.0,
    // src/algorithm.rs (CRC_32_ISO_HDLC, CRC_32_ISCSI, CRC_64_NVME).
    #[test]
    fn each_crc_matches_its_catalogue_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc64nvme(b"123456789"), 0xae8b_1486_0a79_9888);
    }

    #[test]
    fn the_crc_of_nothing_is_zero() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc64nvme(b""), 0);
    }

    // The S3 streaming-with-trailers example uploads 66,560 bytes of 'a' and
    // sends the trailer `x-amz-checksum-crc32c:sOO8/Q==`.
    #[test]
    fn crc32c_matches_the_s3_trailer_example() {
        let data = vec![b'a'; 66_560];
        assert_eq!(base64(&crc32c(&data).to_be_bytes()), "sOO8/Q==");
    }

    // RFC 1321, appendix A.5.
    #[test]
    fn md5_matches_the_rfc_1321_test_suite() {
        let cases: [(&[u8], &str); 7] = [
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                hex(&md5(input)),
                expected,
                "md5 of {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn md5_handles_lengths_around_the_padding_boundary() {
        // 55 bytes fits the length in the same block, 56 needs a second one.
        assert_eq!(hex(&md5(&[b'a'; 55])), "ef1772b6dff9a122358552954ad0df65");
        assert_eq!(hex(&md5(&[b'a'; 56])), "3b0c8ac703f828b04c6c197006d17218");
        assert_eq!(hex(&md5(&[b'a'; 64])), "014842d480b571495a4a0363793f7367");
    }

    #[test]
    fn sha256_of_abc_matches_fips_180_2() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // RFC 4648, section 10.
    #[test]
    fn base64_matches_rfc_4648() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in cases {
            assert_eq!(base64(input.as_bytes()), expected);
        }
    }

    #[test]
    fn base64_uses_plus_and_slash() {
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }
}

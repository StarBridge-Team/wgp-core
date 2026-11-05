//! U/ 房间码派生（13 文档的唯一权威实现）。
//!
//! 从 (房间名称, 房间密钥) 确定性派生 16 字符房间码：
//! `U/` + 4×4 字符，末 2 位 = 命中时的进制（10..=36）。
//!
//! 安全边界（13 §6）：MD5 仅作**标识符派生**，非认证、非加密、非签名；
//! 房间密钥不参与任何密钥材料派生，泄漏 U/ 码不影响会话加密。
//!
//! 本模块自实现 MD5 以维持 wgp-proto 的「零依赖」纪律（00 §3）。

/// MD5 输出长度（字节）
pub const ROOM_CODE_LEN: usize = 16;

/// 单轮扫掠的进制下界（index 从 36 递减到 11，`index < 11` 触发降级）
const BASE_MIN: u32 = 11;
/// 单轮扫掠的进制上界（`index` 复位值，首轮 -1 得 36）
const BASE_RESET: u32 = 37;
/// 命中截取长度（14 → 13 → 12 降级；<=0 兜底）
const IF_INDEX_START: usize = 14;
/// 房间码主体长度（不含末 2 位进制）
const BODY_LEN: usize = 14;

/// 从 (房间名称, 房间密钥) 确定性派生 U/ 房间码（13 §2 算法规范）。
///
/// 同输入恒同输出，跨语言/跨平台一致。末 2 位为命中时的进制。
pub fn derive_room_code(name: &str, key: &str) -> String {
    let mut index: u32 = BASE_RESET;
    let mut ifindex: usize = IF_INDEX_START;

    let temp = loop {
        index -= 1;
        let raw = format!("{name}{index}{key}");
        let num = u128::from_be_bytes(md5(raw.as_bytes()));
        let result = to_base(num, index);

        // 去末尾 '0' 后截取前 ifindex 位
        let trimmed = result.trim_end_matches('0');
        let mut candidate: String = trimmed.chars().take(ifindex).collect();
        // 消歧补丁：'I'→'1'，'O'→'0'（1:1 替换，长度不变）
        candidate = candidate
            .chars()
            .map(|c| match c {
                'I' => '1',
                'O' => '0',
                other => other,
            })
            .collect();

        if candidate.chars().count() == ifindex {
            break candidate; // 命中
        }

        // 极端输入保险：整轮扫掠无命中则降级 ifindex 重来
        if index < BASE_MIN {
            index = BASE_RESET;
            if ifindex == 0 {
                break "A".repeat(BODY_LEN);
            }
            ifindex -= 1;
        }
    };

    // temp + 'A' 补位到 14 字符 + 2 位命中进制
    let mut body = temp;
    while body.chars().count() < BODY_LEN {
        body.push('A');
    }
    let full = format!("{body}{index:02}");

    // 按 4 字符分组、'-' 连接、前缀 "U/"
    let chars: Vec<char> = full.chars().collect();
    let mut grouped = String::with_capacity(full.len() + 3);
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            grouped.push('-');
        }
        grouped.push(*c);
    }
    format!("U/{grouped}")
}

/// u128 → 任意进制字符串（字符表 `0-9A-Z`，大写）
fn to_base(mut num: u128, base: u32) -> String {
    const DIGITS: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if num == 0 {
        return "0".to_string();
    }
    let base = base as u128;
    let mut out = Vec::new();
    while num > 0 {
        let d = (num % base) as usize;
        out.push(DIGITS[d]);
        num /= base;
    }
    out.reverse();
    // 字符表仅含 ASCII，UTF-8 解码不会失败
    String::from_utf8(out).unwrap_or_else(|_| String::new())
}

/// 自实现 MD5（RFC 1321）。仅用于标识符派生，不作任何安全承诺（13 §6）。
pub fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    // 填充：0x80 后补 0 至 ≡56 (mod 64)，末尾 8 字节小端位长
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, slot) in m.iter_mut().enumerate() {
            *slot = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(tmp.rotate_left(S[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: [u8; 16]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn md5_rfc1321_vectors() {
        assert_eq!(hex(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
    }

    #[test]
    fn standard_vectors_match_doc13() {
        assert_eq!(derive_room_code("示例房间", "123456"), "U/C2G9-GYET-311W-R636");
        assert_eq!(derive_room_code("test-room", "abc123"), "U/6U01-TWHM-B7H0-CV36");
        assert_eq!(derive_room_code("MC联机", "9999"), "U/48WY-WMLN-8XDA-FA36");
        assert_eq!(derive_room_code("a", "b"), "U/8SRU-FM1Q-XTDQ-LL36");
    }

    #[test]
    fn format_is_stable() {
        let code = derive_room_code("任意房间", "任意密钥");
        let body = code.strip_prefix("U/").unwrap();
        let parts: Vec<&str> = body.split('-').collect();
        assert_eq!(parts.len(), 4, "4×4 分组");
        for p in &parts {
            assert_eq!(p.chars().count(), 4, "每组 4 字符");
        }
        let flat: String = parts.concat();
        assert_eq!(flat.chars().count(), 16);
        let tail: u32 = flat[14..16].parse().unwrap();
        assert!((10..=36).contains(&tail), "末 2 位进制 ∈ [10,36]，得到 {tail}");
    }

    #[test]
    fn derivation_is_deterministic_and_sensitive() {
        assert_eq!(
            derive_room_code("room", "key"),
            derive_room_code("room", "key")
        );
        assert_ne!(
            derive_room_code("room", "key"),
            derive_room_code("room", "key2")
        );
    }

    #[test]
    fn disambiguation_patch_applied() {
        // 全空间搜索一个会产生 'I'/'O' 的输入，确认补丁生效（不出现 I/O）
        for n in 0..2000u32 {
            let code = derive_room_code(&format!("n{n}"), &format!("k{n}"));
            let body = code.strip_prefix("U/").unwrap();
            assert!(
                !body.contains('I') && !body.contains('O'),
                "消歧补丁失效：{code}"
            );
        }
    }
}

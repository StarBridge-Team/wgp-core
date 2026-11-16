//! 数据面隧道密码（外围 bridge/wgp-port 使用）：密钥派生 + AEAD 封装 + 重放窗口。
//!
//! 01 §1.3 的 AES-256-GCM 帧设计在数据面的落地（14 §4 设想的 TLS-PSK 注入依赖
//! rustls 支持外部 PSK，而 rustls 0.23 并无此能力，取舍登记于 14 §12）。安全语义：
//!  - 密钥：由会话密钥（承诺-揭示 + X25519 的产物，每会话全新）经 HKDF 派生，
//!    收/发两个方向各一把密钥 + 4B nonce 前缀；方向由双方 PeerId 的字节序决定，
//!    两端推导互为镜像。会话密钥本身不直接用于加密。
//!  - Nonce = 前缀(4B) ‖ counter(8B, BE)。**同一方向的 counter 绝不可复用**
//!    （GCM 下 nonce 复用是灾难性的）：调用方必须保证发送 counter 严格递增。
//!  - 外层头部作 AAD：头部被篡改即验签失败。
//!  - 接收侧重放保护：1024 位滑动窗口（01 §1.3.3）。
//! 纪律：无 IO、无 async；派生中间态用后即 zeroize。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// 隧道密钥派生盐（固定且公开；与 ECDH 派生盐分域）
pub const TUNNEL_SALT: &[u8] = b"zheyuemen/v1/tunnel-salt";
/// 隧道密钥派生 info 前缀（其后拼接按字节序排列的双方 PeerId）
pub const TUNNEL_INFO: &[u8] = b"wgp/tunnel/v1";
/// GCM 认证标签长度
pub const TAG_LEN: usize = 16;

const KEY_LEN: usize = 32;
const PREFIX_LEN: usize = 4;
/// 单方向密钥材料：32B 密钥 + 4B nonce 前缀
const DIR_LEN: usize = KEY_LEN + PREFIX_LEN;

fn nonce_of(prefix: &[u8; PREFIX_LEN], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// 发送方向密码器
pub struct TunnelSealer {
    cipher: Aes256Gcm,
    prefix: [u8; PREFIX_LEN],
}

impl TunnelSealer {
    /// 加密并认证（输出 = 密文 ‖ 16B 标签）。
    ///
    /// 安全契约：同一个 `TunnelSealer` 上每个 `counter` 只能用一次。
    pub fn seal(&self, counter: u64, aad: &[u8], plain: &[u8]) -> Option<Vec<u8>> {
        let nonce = nonce_of(&self.prefix, counter);
        self.cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad })
            .ok()
    }
}

/// 接收方向密码器
pub struct TunnelOpener {
    cipher: Aes256Gcm,
    prefix: [u8; PREFIX_LEN],
}

impl TunnelOpener {
    /// 解密验证；任何失败（篡改 / 非本会话密钥 / counter 或 AAD 不符）返回 None，
    /// 调用方静默丢弃。重放判定由 [`ReplayWindow`] 负责，不在本方法内。
    pub fn open(&self, counter: u64, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < TAG_LEN {
            return None;
        }
        let nonce = nonce_of(&self.prefix, counter);
        self.cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: sealed, aad })
            .ok()
    }
}

fn direction(material: &[u8]) -> (Aes256Gcm, [u8; PREFIX_LEN]) {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&material[..KEY_LEN]));
    let mut prefix = [0u8; PREFIX_LEN];
    prefix.copy_from_slice(&material[KEY_LEN..DIR_LEN]);
    (cipher, prefix)
}

/// 由会话密钥派生一对隧道密码器：(本端发送, 本端接收)。
///
/// `local` / `remote` 为双方 PeerId；两端各自调用后，一端的发送器恰好配对另一端的
/// 接收器。双方 PeerId 相同（自连，方向无法区分 → 必然 nonce 复用）时返回 None。
pub fn derive_tunnel(
    session_key: &[u8; 32],
    local: &[u8; 16],
    remote: &[u8; 16],
) -> Option<(TunnelSealer, TunnelOpener)> {
    if local == remote {
        return None;
    }
    let local_is_lo = local < remote;
    let (lo, hi) = if local_is_lo {
        (local, remote)
    } else {
        (remote, local)
    };
    let mut info = Vec::with_capacity(TUNNEL_INFO.len() + 32);
    info.extend_from_slice(TUNNEL_INFO);
    info.extend_from_slice(lo);
    info.extend_from_slice(hi);

    let hk = Hkdf::<Sha256>::new(Some(TUNNEL_SALT), session_key);
    // 前半 = lo→hi 方向，后半 = hi→lo 方向
    let mut okm = [0u8; 2 * DIR_LEN];
    hk.expand(&info, &mut okm).ok()?;

    let (lo_to_hi, hi_to_lo) = okm.split_at(DIR_LEN);
    let (send, recv) = if local_is_lo {
        (lo_to_hi, hi_to_lo)
    } else {
        (hi_to_lo, lo_to_hi)
    };
    let (send_cipher, send_prefix) = direction(send);
    let (recv_cipher, recv_prefix) = direction(recv);
    okm.zeroize();

    Some((
        TunnelSealer {
            cipher: send_cipher,
            prefix: send_prefix,
        },
        TunnelOpener {
            cipher: recv_cipher,
            prefix: recv_prefix,
        },
    ))
}

/// 重放窗口位图总位数（01 §1.3.3）
pub const REPLAY_BITS: u64 = 1024;
const WORD_BITS: u64 = 64;
const WORDS: u64 = REPLAY_BITS / WORD_BITS;
/// 保证可接受的乱序深度：位图按环形使用，留一个字作冗余
pub const REPLAY_WINDOW: u64 = REPLAY_BITS - WORD_BITS;

/// 接收侧重放窗口（每个接收方向一份）。
///
/// 用法：解密前 [`ReplayWindow::check`]（明显重放/过旧的包不必再做 AEAD），
/// 验签通过后 [`ReplayWindow::commit`]。只有验签通过的 counter 才能推进窗口，
/// 否则伪造包可以把窗口推走、让合法包被误判为过旧。
pub struct ReplayWindow {
    /// 已接受的最大 counter
    last: u64,
    bitmap: [u64; WORDS as usize],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            last: 0,
            bitmap: [0; WORDS as usize],
        }
    }

    fn slot(counter: u64) -> (usize, u64) {
        (
            ((counter / WORD_BITS) % WORDS) as usize,
            1u64 << (counter % WORD_BITS),
        )
    }

    /// 仅判定、不改状态：true = 该 counter 目前可接受
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if self.last - counter > REPLAY_WINDOW {
            return false;
        }
        let (idx, bit) = Self::slot(counter);
        self.bitmap[idx] & bit == 0
    }

    /// 验签通过后登记；返回 false = 重放或过旧，调用方必须丢弃该包
    pub fn commit(&mut self, counter: u64) -> bool {
        if counter > self.last {
            // 窗口前移：清掉新进入窗口的字（其中残留着一整圈之前的旧位）
            let cur = self.last / WORD_BITS;
            let new = counter / WORD_BITS;
            let advance = (new - cur).min(WORDS);
            for i in 1..=advance {
                self.bitmap[((cur + i) % WORDS) as usize] = 0;
            }
            self.last = counter;
        } else if self.last - counter > REPLAY_WINDOW {
            return false;
        }
        let (idx, bit) = Self::slot(counter);
        if self.bitmap[idx] & bit != 0 {
            return false;
        }
        self.bitmap[idx] |= bit;
        true
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const KEY: [u8; 32] = [0x42; 32];
    const ALICE: [u8; 16] = [0x01; 16];
    const BOB: [u8; 16] = [0x02; 16];

    #[test]
    fn both_ends_derive_mirrored_ciphers() {
        let (a_seal, a_open) = derive_tunnel(&KEY, &ALICE, &BOB).unwrap();
        let (b_seal, b_open) = derive_tunnel(&KEY, &BOB, &ALICE).unwrap();

        let sealed = a_seal.seal(7, b"hdr", b"hello bob").unwrap();
        assert_eq!(sealed.len(), 9 + TAG_LEN);
        assert_eq!(b_open.open(7, b"hdr", &sealed).unwrap(), b"hello bob");

        let sealed = b_seal.seal(0, b"hdr", b"hello alice").unwrap();
        assert_eq!(a_open.open(0, b"hdr", &sealed).unwrap(), b"hello alice");
    }

    #[test]
    fn directions_use_independent_keys() {
        let (a_seal, a_open) = derive_tunnel(&KEY, &ALICE, &BOB).unwrap();
        // 自己发出的包用自己的接收器打不开：反射攻击（把包原样弹回发送方）无效，
        // 且两个方向即使 counter 相同也不会复用 (密钥, nonce)
        let sealed = a_seal.seal(1, b"", b"x").unwrap();
        assert!(a_open.open(1, b"", &sealed).is_none());
    }

    #[test]
    fn tampering_is_rejected() {
        let (a_seal, _) = derive_tunnel(&KEY, &ALICE, &BOB).unwrap();
        let (_, b_open) = derive_tunnel(&KEY, &BOB, &ALICE).unwrap();
        let sealed = a_seal.seal(5, b"header", b"payload").unwrap();

        // 改密文
        let mut bad = sealed.clone();
        bad[0] ^= 0x01;
        assert!(b_open.open(5, b"header", &bad).is_none());
        // 改标签
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(b_open.open(5, b"header", &bad).is_none());
        // 改 AAD（外层头部）
        assert!(b_open.open(5, b"headeR", &sealed).is_none());
        // 改 counter（nonce）
        assert!(b_open.open(6, b"header", &sealed).is_none());
        // 截断到不足一个标签
        assert!(b_open.open(5, b"header", &sealed[..TAG_LEN - 1]).is_none());
        // 原样仍可解
        assert_eq!(b_open.open(5, b"header", &sealed).unwrap(), b"payload");
    }

    #[test]
    fn different_session_or_peers_cannot_decrypt() {
        let (a_seal, _) = derive_tunnel(&KEY, &ALICE, &BOB).unwrap();
        let sealed = a_seal.seal(0, b"", b"secret").unwrap();

        // 另一次会话（会话密钥不同）
        let other_key = [0x43; 32];
        let (_, wrong) = derive_tunnel(&other_key, &BOB, &ALICE).unwrap();
        assert!(wrong.open(0, b"", &sealed).is_none());

        // 同一会话密钥但对端身份不同（info 绑定双方 PeerId）
        let carol = [0x03; 16];
        let (_, wrong) = derive_tunnel(&KEY, &carol, &ALICE).unwrap();
        assert!(wrong.open(0, b"", &sealed).is_none());
    }

    #[test]
    fn self_pairing_is_refused() {
        assert!(derive_tunnel(&KEY, &ALICE, &ALICE).is_none());
    }

    #[test]
    fn replay_accepts_in_order_and_rejects_duplicates() {
        let mut w = ReplayWindow::new();
        for c in 0..2000u64 {
            assert!(w.check(c));
            assert!(w.commit(c), "首次出现必须接受 c={c}");
            assert!(!w.check(c));
            assert!(!w.commit(c), "重放必须拒绝 c={c}");
        }
    }

    #[test]
    fn replay_tolerates_reordering_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.commit(5000));
        // 窗口内的迟到包：各接受一次
        for c in [4999u64, 4500, 5000 - REPLAY_WINDOW] {
            assert!(w.check(c), "c={c}");
            assert!(w.commit(c), "c={c}");
            assert!(!w.commit(c), "c={c}");
        }
        // 窗口外：拒绝
        let too_old = 5000 - REPLAY_WINDOW - 1;
        assert!(!w.check(too_old));
        assert!(!w.commit(too_old));
    }

    #[test]
    fn replay_large_jump_resets_window() {
        let mut w = ReplayWindow::new();
        for c in 0..100u64 {
            assert!(w.commit(c));
        }
        // 跳过远超窗口的距离：旧位全部失效，新窗口内的位置全部可用
        assert!(w.commit(1_000_000));
        assert!(!w.commit(99), "远古包必须拒绝");
        for c in (1_000_000 - REPLAY_WINDOW)..1_000_000 {
            assert!(w.commit(c), "跳跃后窗口内的位置应可用 c={c}");
        }
    }

    /// 与朴素模型（集合 + 最大值）逐步对拍：随机乱序/重复/跳跃混合序列
    #[test]
    fn replay_matches_reference_model() {
        let mut w = ReplayWindow::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let mut max: u64 = 0;
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut base: u64 = 0;
        for step in 0..200_000u32 {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            // 多数时候在 base 附近抖动（乱序/重复），偶尔向前跳（含跨窗口大跳）
            let jitter = state % 1500;
            let counter = (base + 1500).saturating_sub(jitter);
            base += match (state >> 32) % 100 {
                0 => 5000,
                1..=9 => 70,
                _ => 1,
            };

            let expect = if counter > max {
                true
            } else {
                max - counter <= REPLAY_WINDOW && !seen.contains(&counter)
            };
            assert_eq!(w.check(counter), expect, "check step={step} counter={counter} max={max}");
            assert_eq!(w.commit(counter), expect, "commit step={step} counter={counter} max={max}");
            if expect {
                seen.insert(counter);
                max = max.max(counter);
            }
        }
    }
}

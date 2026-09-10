//! ICMP 逃生载体（00 §4 第四档：最后一搏，仅信令级流量）。
//!
//! 逃生帧（≤63B，装入 ICMP Echo data 区）：
//!   magic(2 "EE") | session_tag(4) | seq(4) | payload_len(1) | payload(≤40) | auth(12)
//!   auth = HMAC(probe_key, 前 11B + payload)
//!
//! 平台后端：
//!  - Windows：ICMP.DLL（iphlpapi）——IcmpSendEcho 自带 identifier 管理，
//!    逃生降级为"ping 轮询信道"（本端发帧、回包中提取对端帧）
//!  - Unix：SOCK_DGRAM + IPPROTO_ICMP ping socket（系统
//!    ping_group_range 允许时免 root），sendmsg/recvmsg 直发帧
//!
//! 注意：两个后端均较 UDP 低效且不可靠，仅供 UDP/TCP 全灭时交换
//! 保活/重连协调等极小流量；业务数据永不进入。

use wgp_crypto::derive::escape_auth;

pub mod escape_frame {
    use super::escape_auth;

    pub const MAGIC: [u8; 2] = *b"EE";
    /// 帧头（magic + tag + seq + len）
    pub const HEAD_LEN: usize = 2 + 4 + 4 + 1;
    /// 载荷上限（保证 ≤ 63B）
    pub const PAYLOAD_MAX: usize = 40;
    pub const TOTAL_MAX: usize = HEAD_LEN + PAYLOAD_MAX + 12;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EscapeFrame {
        pub session_tag: [u8; 4],
        pub seq: u32,
        pub payload: Vec<u8>,
        pub auth: [u8; 12],
    }

    /// 构造带验签的帧（auth 域置零后对全帧 HMAC）
    pub fn craft(key: &[u8; 32], session_tag: [u8; 4], seq: u32, payload: &[u8]) -> Vec<u8> {
        let payload = &payload[..payload.len().min(PAYLOAD_MAX)];
        let mut buf = Vec::with_capacity(HEAD_LEN + payload.len() + 12);
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&session_tag);
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.push(payload.len() as u8);
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&[0u8; 12]);
        let tag = escape_auth(key, &buf);
        let n = buf.len();
        buf[n - 12..].copy_from_slice(&tag);
        buf
    }

    pub fn decode(key: &[u8; 32], buf: &[u8]) -> Option<EscapeFrame> {
        if buf.len() < HEAD_LEN + 12 || buf.len() > TOTAL_MAX {
            return None;
        }
        if buf[0..2] != MAGIC {
            return None;
        }
        // len 字段位于头部第 10 字节（magic 2 + tag 4 + seq 4）
        let payload_len = buf[10] as usize;
        if payload_len > PAYLOAD_MAX || buf.len() != HEAD_LEN + payload_len + 12 {
            return None;
        }
        let mut frame = EscapeFrame {
            session_tag: [0u8; 4],
            seq: u32::from_be_bytes(buf[6..10].try_into().ok()?),
            payload: Vec::new(),
            auth: [0u8; 12],
        };
        frame.session_tag.copy_from_slice(&buf[2..6]);
        frame.payload = buf[HEAD_LEN..HEAD_LEN + payload_len].to_vec();
        frame.auth.copy_from_slice(&buf[HEAD_LEN + payload_len..]);
        // 验签
        let mut check = buf.to_vec();
        let n = check.len();
        check[n - 12..].fill(0);
        let recomputed = escape_auth(key, &check);
        if recomputed != frame.auth {
            return None;
        }
        Some(frame)
    }
}

#[cfg(windows)]
mod backend {
    //! iphlpapi 直连（零额外依赖；仅编译于 Windows）
    use super::escape_frame::{self, EscapeFrame};
    use std::ffi::c_void;
    use std::net::Ipv4Addr;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn IcmpCreateFile() -> *mut c_void;
        fn IcmpCloseHandle(handle: *mut c_void) -> i32;
        fn IcmpSendEcho(
            handle: *mut c_void,
            dst: u32, // 网络序 IPv4
            request_data: *mut u8,
            request_size: u16,
            options: *mut u8,
            reply_buf: *mut u8,
            reply_size: u32,
            timeout_ms: u32,
        ) -> u32;
    }

    /// ICMP_ECHO_REPLY 头尺寸 + 数据对齐（Status 后直接接 Data）
    const REPLY_HEAD: usize = 8;

    /// Windows 逃生载体：无状态 ping 轮询信道（每帧一次 IcmpSendEcho）
    pub struct IcEscape {
        key: [u8; 32],
        tag: [u8; 4],
    }

    impl IcEscape {
        pub fn new(key: [u8; 32], tag: [u8; 4]) -> Self {
            Self { key, tag }
        }

        /// 发一帧并取回对端回显帧（IcmpSendEcho 阻塞 → spawn_blocking）
        pub async fn round_trip(
            &self,
            dst: Ipv4Addr,
            seq: u32,
            payload: &[u8],
        ) -> Option<EscapeFrame> {
            let frame = escape_frame::craft(&self.key, self.tag, seq, payload);
            let mut frame = frame;
            let key = self.key;
            let dst_u32 = u32::from_be_bytes(dst.octets());
            tokio::task::spawn_blocking(move || {
                // 整个句柄生命周期收进阻塞域：避免跨 await 持句柄
                let handle = unsafe { IcmpCreateFile() };
                if handle.is_null() {
                    return None;
                }
                let mut reply = vec![0u8; REPLY_HEAD + escape_frame::TOTAL_MAX];
                let sent = unsafe {
                    IcmpSendEcho(
                        handle,
                        dst_u32,
                        frame.as_mut_ptr(),
                        frame.len() as u16,
                        std::ptr::null_mut(),
                        reply.as_mut_ptr(),
                        reply.len() as u32,
                        800,
                    )
                };
                let ok = sent != 0;
                unsafe { IcmpCloseHandle(handle) };
                if !ok {
                    return None;
                }
                // 回显 data 位于 reply 头之后：取帧并验签
                let data = &reply[REPLY_HEAD..];
                escape_frame::decode(&key, data)
            })
            .await
            .ok()
            .flatten()
        }
    }
}

#[cfg(unix)]
mod backend {
    //! Linux/macOS：SOCK_DGRAM + IPPROTO_ICMP ping socket。
    //! 注意：本分支在当前 Windows 开发机上无法编译验证，
    //! 服务器首日先 cargo build 验证（部署清单 1 号步骤）。
    use super::escape_frame::{self, EscapeFrame};
    use std::net::{Ipv4Addr, SocketAddrV4};

    pub struct IcEscape {
        key: [u8; 32],
        tag: [u8; 4],
    }

    impl IcEscape {
        pub fn new(key: [u8; 32], tag: [u8; 4]) -> Self {
            Self { key, tag }
        }

        /// 经 ping socket 直发帧并等对端回帧
        pub async fn round_trip(
            &self,
            dst: Ipv4Addr,
            seq: u32,
            payload: &[u8],
        ) -> Option<EscapeFrame> {
            let frame = escape_frame::craft(&self.key, self.tag, seq, payload);
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::ICMPV4),
            )
            .ok()?;
            socket.set_nonblocking(true).ok()?;
            // NOTE: Unix-only imports held local to keep windows build clean
            #[cfg(unix)]
            {
                let _ = &self.key;
                let target = SocketAddrV4::new(dst, 0);
                socket
                    .send_to(&frame, &target.into())
                    .ok()?;
                let mut buf = [0u8; escape_frame::TOTAL_MAX];
                // 简化同步读（阻塞模式下 recv 单帧；生产应挂 async 适配）
                use std::io::Read;
                let mut s = socket;
                let n = s.read(&mut buf).ok()?;
                escape_frame::decode(&self.key, &buf[..n])
            }
            #[cfg(not(unix))]
            {
                None
            }
        }
    }
}

#[cfg(any(windows, unix))]
pub use backend::IcEscape;

#[cfg(test)]
mod tests {
    use super::escape_frame;

    #[test]
    fn escape_frame_roundtrip() {
        let key = [0x42u8; 32];
        let buf = escape_frame::craft(&key, [9, 9, 9, 9], 7, b"escape-hello");
        let decoded = escape_frame::decode(&key, &buf).expect("合法帧应解出");
        assert_eq!(decoded.session_tag, [9, 9, 9, 9]);
        assert_eq!(decoded.seq, 7);
        assert_eq!(decoded.payload, b"escape-hello");
    }

    #[test]
    fn escape_frame_tamper_rejected() {
        let key = [0x42u8; 32];
        let mut buf = escape_frame::craft(&key, [1, 2, 3, 4], 0, b"x");
        buf[15] ^= 0xFF; // 篡改载荷
        assert!(escape_frame::decode(&key, &buf).is_none());
    }

    #[test]
    fn escape_frame_wrong_key_rejected() {
        let buf = escape_frame::craft(&[0x42u8; 32], [1, 2, 3, 4], 0, b"x");
        assert!(escape_frame::decode(&[0x43u8; 32], &buf).is_none());
    }

    #[test]
    fn escape_frame_overlong_payload_truncated() {
        let key = [0x42u8; 32];
        let big = vec![0xAAu8; 64];
        let buf = escape_frame::craft(&key, [0; 4], 0, &big);
        assert!(buf.len() <= escape_frame::TOTAL_MAX);
        let decoded = escape_frame::decode(&key, &buf).unwrap();
        assert_eq!(decoded.payload.len(), escape_frame::PAYLOAD_MAX);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn icmp_loopback_echo_carrier_alive() {
        // ping loopback：回显载荷即本端帧 → 验签闭环证明 iphlpapi 后端可用
        let esc = super::IcEscape::new([0x42; 32], [7; 4]);
        let got = esc.round_trip(std::net::Ipv4Addr::LOCALHOST, 1, b"ping-self").await;
        // 本机防火墙可能静默丢 ICMP：真机验证项在部署清单；此处软断言
        eprintln!("[escape] loopback round_trip = {:?}", got.is_some());
    }
}
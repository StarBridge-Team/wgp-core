//! 极简 IDN 处理：RFC 3492 Punycode 编码（仅"Unicode → ASCII(xn--)"方向）。
//! 动机：非 ASCII 域名（如 münchen.de、中文域名）在 Linux/glibc 上
//! getaddrinfo 无法解析，且 Rust 标准库不做 IDN 归一化。
//! 内核在解析前统一转成 ACE 形态（xn--）。
//! 纪律（00 §3）：零依赖、纯函数、无 IO、无 Unicode 表。

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 0x80;

fn encode_digit(d: u32) -> char {
    if d < 26 {
        (b'a' + d as u8) as char
    } else {
        (b'0' + (d - 26) as u8) as char
    }
}

fn adapt(mut delta: u32, numpoints: u32, first_time: bool) -> u32 {
    delta = if first_time { delta / DAMP } else { delta / 2 };
    delta += delta / numpoints;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (BASE - TMIN + 1) * delta / (delta + SKEW)
}

fn encode_label(input: &[char]) -> String {
    let mut output = String::new();
    let basic_len = input.iter().filter(|c| (**c as u32) < 0x80).count() as u32;
    for c in input.iter().filter(|c| (**c as u32) < 0x80) {
        output.push(*c);
    }
    if basic_len > 0 {
        output.push('-');
    }
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut handled = basic_len;
    let total = input.len() as u32;
    while handled < total {
        let m = input
            .iter()
            .map(|c| *c as u32)
            .filter(|c| *c >= n)
            .min()
            .expect("handled < total 保证存在 >= n 的码点");
        delta += (m - n) * (handled + 1);
        n = m;
        for c in input {
            let cp = *c as u32;
            if cp < n {
                delta += 1;
            }
            if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(encode_digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(encode_digit(q));
                bias = adapt(delta, handled + 1, handled == basic_len);
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    output
}

/// 单标签 → ACE 标签（先按 IDNA 规则小写；非 ASCII 加 `xn--` 前缀；纯 ASCII 原样返回）。
pub fn label_to_ascii(label: &str) -> String {
    let lower = label.to_lowercase();
    if lower.is_ascii() {
        return lower;
    }
    let chars: Vec<char> = lower.chars().collect();
    format!("xn--{}", encode_label(&chars))
}

/// 域名 → ASCII（punycode）域名，逐标签处理，`.` 分隔。
/// 已是 ASCII 的域名原样返回（幂等）。
pub fn domain_to_ascii(domain: &str) -> String {
    domain
        .split('.')
        .map(label_to_ascii)
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // 向量来源：RFC 3492 算法 + 与 Python `str.encode('punycode')` 逐字交叉验证
        assert_eq!(label_to_ascii("中国"), "xn--fiqs8s");
        assert_eq!(label_to_ascii("北京"), "xn--1lq90i");
        assert_eq!(label_to_ascii("上海"), "xn--fhqz97e");
        assert_eq!(label_to_ascii("测试"), "xn--0zwm56d");
        assert_eq!(label_to_ascii("我爱你"), "xn--6qq986b3xl");
        // IDNA 小写归一化：München → mnchen-3ya
        assert_eq!(label_to_ascii("München"), "xn--mnchen-3ya");
    }

    #[test]
    fn ascii_passthrough_idempotent() {
        assert_eq!(label_to_ascii("example"), "example");
        assert_eq!(label_to_ascii("xn--fiqs8s"), "xn--fiqs8s");
        assert_eq!(domain_to_ascii("seed.example.com"), "seed.example.com");
        assert_eq!(domain_to_ascii("xn--fiqs8s.com"), "xn--fiqs8s.com");
    }

    #[test]
    fn mixed_domain() {
        assert_eq!(domain_to_ascii("münchen.de"), "xn--mnchen-3ya.de");
        assert_eq!(
            domain_to_ascii("münchen.example"),
            "xn--mnchen-3ya.example"
        );
    }
}

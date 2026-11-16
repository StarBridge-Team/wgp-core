//! 半开区间集合 `[start, end)`：可靠层的确认记账（报文号区间 / 字节流偏移区间）。
//! 不变式：区间互不重叠、互不相邻（相邻即合并），按起点有序。

use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub(crate) struct RangeSet {
    /// start → end（end 不含）
    map: BTreeMap<u64, u64>,
}

impl RangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 区间个数
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// 插入 `[start, end)`，与相交或相邻的既有区间合并
    pub fn insert(&mut self, mut start: u64, mut end: u64) {
        if start >= end {
            return;
        }
        // 前驱（起点 ≤ start 的最后一个）若触及本区间，则并入
        if let Some((&s, &e)) = self.map.range(..=start).next_back() {
            if e >= start {
                if e >= end {
                    return; // 完全被覆盖
                }
                start = s;
            }
        }
        // 吸收所有起点落在 [start, end] 内的后继
        let absorbed: Vec<u64> = self
            .map
            .range(start..=end)
            .map(|(&s, &e)| {
                if e > end {
                    end = e;
                }
                s
            })
            .collect();
        for s in absorbed {
            self.map.remove(&s);
        }
        self.map.insert(start, end);
    }

    /// 移除 `[start, end)`（可能把既有区间切成两段）
    pub fn remove(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let mut touched: Vec<(u64, u64)> = Vec::new();
        if let Some((&s, &e)) = self.map.range(..start).next_back() {
            if e > start {
                touched.push((s, e));
            }
        }
        for (&s, &e) in self.map.range(start..end) {
            touched.push((s, e));
        }
        for (s, e) in touched {
            self.map.remove(&s);
            if s < start {
                self.map.insert(s, start);
            }
            if e > end {
                self.map.insert(end, e);
            }
        }
    }

    /// 丢弃所有低于 `floor` 的部分
    pub fn remove_below(&mut self, floor: u64) {
        self.remove(0, floor);
    }

    #[cfg(test)]
    pub fn contains(&self, x: u64) -> bool {
        self.map
            .range(..=x)
            .next_back()
            .is_some_and(|(_, &e)| x < e)
    }

    /// 最低的区间
    pub fn first(&self) -> Option<(u64, u64)> {
        self.map.iter().next().map(|(&s, &e)| (s, e))
    }

    /// 最高的区间
    #[cfg(test)]
    pub fn last(&self) -> Option<(u64, u64)> {
        self.map.iter().next_back().map(|(&s, &e)| (s, e))
    }

    /// 弹出最低的区间
    pub fn pop_first(&mut self) -> Option<(u64, u64)> {
        let (s, e) = self.first()?;
        self.map.remove(&s);
        Some((s, e))
    }

    /// 自高向低遍历
    pub fn iter_desc(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.map.iter().rev().map(|(&s, &e)| (s, e))
    }

    /// `[start, end)` 中**未**被本集合覆盖的子区间（升序）
    pub fn gaps_within(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut gaps = Vec::new();
        if start >= end {
            return gaps;
        }
        let mut cursor = start;
        if let Some((_, &e)) = self.map.range(..=start).next_back() {
            if e > cursor {
                cursor = e;
            }
        }
        for (&s, &e) in self.map.range(start..end) {
            if s > cursor {
                gaps.push((cursor, s.min(end)));
            }
            if e > cursor {
                cursor = e;
            }
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            gaps.push((cursor, end));
        }
        gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(r: &RangeSet) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = r.iter_desc().collect();
        v.reverse();
        v
    }

    #[test]
    fn insert_merges_overlapping_and_adjacent() {
        let mut r = RangeSet::new();
        r.insert(10, 20);
        r.insert(30, 40);
        assert_eq!(all(&r), vec![(10, 20), (30, 40)]);
        r.insert(20, 30); // 恰好填平空洞：三段并一段
        assert_eq!(all(&r), vec![(10, 40)]);
        r.insert(5, 12); // 左侧相交
        r.insert(38, 50); // 右侧相交
        assert_eq!(all(&r), vec![(5, 50)]);
        r.insert(7, 9); // 完全被覆盖
        assert_eq!(all(&r), vec![(5, 50)]);
        r.insert(60, 60); // 空区间忽略
        assert_eq!(r.len(), 1);
        r.insert(0, 100); // 吸收全部
        assert_eq!(all(&r), vec![(0, 100)]);
    }

    #[test]
    fn remove_splits_and_trims() {
        let mut r = RangeSet::new();
        r.insert(0, 100);
        r.remove(40, 60);
        assert_eq!(all(&r), vec![(0, 40), (60, 100)]);
        r.remove(30, 70);
        assert_eq!(all(&r), vec![(0, 30), (70, 100)]);
        r.remove_below(10);
        assert_eq!(all(&r), vec![(10, 30), (70, 100)]);
        r.remove(0, 1000);
        assert!(r.is_empty());
    }

    #[test]
    fn contains_and_ends() {
        let mut r = RangeSet::new();
        r.insert(10, 20);
        r.insert(30, 31);
        assert!(!r.contains(9));
        assert!(r.contains(10));
        assert!(r.contains(19));
        assert!(!r.contains(20));
        assert!(r.contains(30));
        assert_eq!(r.first(), Some((10, 20)));
        assert_eq!(r.last(), Some((30, 31)));
        assert_eq!(r.pop_first(), Some((10, 20)));
        assert_eq!(r.first(), Some((30, 31)));
    }

    #[test]
    fn gaps_within_reports_uncovered_parts() {
        let mut r = RangeSet::new();
        r.insert(10, 20);
        r.insert(30, 40);
        assert_eq!(r.gaps_within(0, 50), vec![(0, 10), (20, 30), (40, 50)]);
        assert_eq!(r.gaps_within(12, 35), vec![(20, 30)]);
        assert_eq!(r.gaps_within(10, 20), vec![]);
        assert_eq!(r.gaps_within(20, 30), vec![(20, 30)]);
        assert_eq!(r.gaps_within(15, 25), vec![(20, 25)]);
        assert_eq!(RangeSet::new().gaps_within(3, 9), vec![(3, 9)]);
    }

    /// 与逐点布尔数组模型对拍（随机插入/删除）
    #[test]
    fn matches_bitmap_model() {
        const N: usize = 400;
        let mut model = [false; N];
        let mut r = RangeSet::new();
        let mut state: u64 = 0x1234_5678_9ABC_DEF1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..5000 {
            let a = (next() % N as u64) as usize;
            let b = (a + (next() % 40) as usize).min(N);
            if next() % 3 == 0 {
                r.remove(a as u64, b as u64);
                model[a..b].iter_mut().for_each(|x| *x = false);
            } else {
                r.insert(a as u64, b as u64);
                model[a..b].iter_mut().for_each(|x| *x = true);
            }
            // 不变式：有序、不相交、不相邻
            let v = all(&r);
            for w in v.windows(2) {
                assert!(w[0].1 < w[1].0, "区间必须有序且不相邻: {v:?}");
            }
            for (i, &m) in model.iter().enumerate() {
                assert_eq!(r.contains(i as u64), m, "i={i}");
            }
            // gaps_within 与模型一致
            let gaps = r.gaps_within(0, N as u64);
            let mut from_gaps = [true; N];
            for (s, e) in gaps {
                from_gaps[s as usize..e as usize]
                    .iter_mut()
                    .for_each(|x| *x = false);
            }
            assert_eq!(from_gaps, model);
        }
    }
}

//! Kademlia 路由表骨架（实现阶段补全：k-bucket 分裂、维护、SeedAdvertise 交换）。

use crate::id::NodeId;

/// k-bucket（K=20 标准；骨架仅保留结构）
pub struct KBucket {
    pub nodes: Vec<NodeId>,
}

impl KBucket {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }
}

/// 路由表：以本节点 ID 为原点，按 XOR 距离分桶
pub struct RoutingTable {
    home: NodeId,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(home: NodeId) -> Self {
        Self {
            home,
            buckets: (0..256).map(|_| KBucket::new()).collect(),
        }
    }

    /// 节点应落入的桶号（最高不同位的位序）
    pub fn bucket_index(&self, id: &NodeId) -> usize {
        let d = self.home.xor_distance(id);
        for (i, b) in d.iter().enumerate() {
            if *b != 0 {
                let bit = b.leading_zeros() as usize;
                return i * 8 + bit;
            }
        }
        0
    }

    pub fn insert(&mut self, id: NodeId) {
        let idx = self.bucket_index(&id);
        self.buckets[idx].nodes.push(id);
    }

    /// 与目标最近的 K 个已知节点（实现阶段：全表排序截断）
    pub fn closest_to(&self, target: &NodeId) -> Vec<NodeId> {
        let mut all: Vec<NodeId> = self.buckets.iter().flat_map(|b| b.nodes.iter().copied()).collect();
        all.sort_by_key(|n| {
            let d = n.xor_distance(target);
            let mut k = [0u8; 32];
            k.copy_from_slice(&d);
            k
        });
        all.truncate(20);
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte0: u8) -> NodeId {
        let mut a = [0u8; 32];
        a[0] = byte0;
        a[31] = 1;
        NodeId(a)
    }

    #[test]
    fn bucket_index_by_leading_bit() {
        let home = NodeId([0u8; 32]);
        let rt = RoutingTable::new(home);
        // 相同节点 → 0
        assert_eq!(rt.bucket_index(&home), 0);
        // 最高位差在第 7 位（0x01）→ bucket 7
        assert_eq!(rt.bucket_index(&id(0x01)), 7);
        // 最高位差在第 0 位（0x80）→ bucket 0
        assert_eq!(rt.bucket_index(&id(0x80)), 0);
        // 第二字节才差 → 8 + 7 = 15
        let mut b = [0u8; 32];
        b[1] = 0x01;
        assert_eq!(rt.bucket_index(&NodeId(b)), 15);
    }

    #[test]
    fn closest_to_sorted_by_xor_distance() {
        let home = NodeId([0u8; 32]);
        let mut rt = RoutingTable::new(home);
        let far = id(0xFF);
        let mid = id(0x08);
        let near = id(0x01);
        rt.insert(far);
        rt.insert(mid);
        rt.insert(near);
        let target = NodeId([0u8; 32]);
        let closest = rt.closest_to(&target);
        assert_eq!(closest.len(), 3);
        // 距离升序：near(1) < mid(8) < far(255)
        assert_eq!(closest[0], near);
        assert_eq!(closest[1], mid);
        assert_eq!(closest[2], far);
    }

    #[test]
    fn closest_to_truncates_to_20() {
        let home = NodeId([0u8; 32]);
        let mut rt = RoutingTable::new(home);
        for i in 0..40u8 {
            let mut a = [0u8; 32];
            a[0] = i + 1;
            rt.insert(NodeId(a));
        }
        assert_eq!(rt.closest_to(&home).len(), 20);
    }
}
//! Minimal unbounded LRU map, replacing `hashlink::LruCache` for the virtual DNS table.
//!
//! Semantics match the subset of `hashlink::LruCache::new_unbounded()` that tun2proxy uses:
//! - `get` / `get_mut` mark the entry as most recently used (move it to the back);
//! - `insert` of a new key appends it at the back (most recently used);
//! - `front` / `iter` start at the least recently used entry;
//! - no capacity, so nothing is ever evicted automatically.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

pub(crate) struct LruCache<K, V> {
    map: HashMap<K, (V, u64)>,
    order: BTreeMap<u64, K>,
    next_tick: u64,
}

impl<K: Hash + Eq + Clone, V> LruCache<K, V> {
    pub(crate) fn new_unbounded() -> Self {
        Self {
            map: HashMap::new(),
            order: BTreeMap::new(),
            next_tick: 0,
        }
    }

    fn tick(&mut self) -> u64 {
        let t = self.next_tick;
        self.next_tick += 1;
        t
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn contains_key(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }

    /// Insert at the back (most recently used). Replaces and moves an existing entry.
    pub(crate) fn insert(&mut self, k: K, v: V) -> Option<V> {
        let t = self.tick();
        let old = self.map.insert(k.clone(), (v, t));
        if let Some((_, old_t)) = &old {
            self.order.remove(old_t);
        }
        self.order.insert(t, k);
        old.map(|(v, _)| v)
    }

    /// Retrieve and mark as most recently used.
    pub(crate) fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let t = self.tick();
        let (v, old_t) = self.map.get_mut(k)?;
        let key = self.order.remove(old_t).expect("lru order out of sync");
        self.order.insert(t, key);
        *old_t = t;
        Some(v)
    }

    /// Retrieve and mark as most recently used.
    pub(crate) fn get(&mut self, k: &K) -> Option<&V> {
        self.get_mut(k).map(|v| &*v)
    }

    pub(crate) fn remove(&mut self, k: &K) -> Option<V> {
        let (v, t) = self.map.remove(k)?;
        self.order.remove(&t);
        Some(v)
    }

    /// Entries from least to most recently used.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.order.values().map(move |k| (k, &self.map[k].0))
    }
}

#[cfg(test)]
mod tests {
    use super::LruCache;

    fn keys(c: &LruCache<u32, &'static str>) -> Vec<u32> {
        c.iter().map(|(k, _)| *k).collect()
    }

    #[test]
    fn insertion_order_is_lru_order() {
        let mut c = LruCache::new_unbounded();
        c.insert(1, "a");
        c.insert(2, "b");
        c.insert(3, "c");
        assert_eq!(keys(&c), vec![1, 2, 3]);
        assert_eq!(c.iter().next(), Some((&1, &"a")));
    }

    #[test]
    fn get_and_get_mut_move_to_back() {
        let mut c = LruCache::new_unbounded();
        c.insert(1, "a");
        c.insert(2, "b");
        c.insert(3, "c");
        assert_eq!(c.get(&1), Some(&"a"));
        assert_eq!(keys(&c), vec![2, 3, 1]);
        *c.get_mut(&2).unwrap() = "B";
        assert_eq!(keys(&c), vec![3, 1, 2]);
        assert_eq!(c.get(&2), Some(&"B"));
        assert_eq!(c.get(&9), None);
        assert_eq!(keys(&c), vec![3, 1, 2]);
    }

    #[test]
    fn remove_and_reinsert() {
        let mut c = LruCache::new_unbounded();
        c.insert(1, "a");
        c.insert(2, "b");
        assert_eq!(c.remove(&1), Some("a"));
        assert_eq!(c.remove(&1), None);
        assert!(!c.contains_key(&1));
        c.insert(1, "a2");
        assert_eq!(keys(&c), vec![2, 1]);
        assert_eq!(c.insert(2, "b2"), Some("b"));
        assert_eq!(keys(&c), vec![1, 2]);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn unbounded_never_evicts() {
        let mut c = LruCache::new_unbounded();
        for i in 0..10_000u32 {
            c.insert(i, "x");
        }
        assert_eq!(c.len(), 10_000);
        assert_eq!(c.iter().next().map(|(k, _)| *k), Some(0));
    }
}

//! 多级缓存：L1-LRU + L2-TTL（与 Go 版 internal/gateway/cache 对齐）

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// L1：进程内 LRU 缓存（默认 maxsize=1024, TTL=60s）
pub struct LruCache {
    capacity: usize,
    default_ttl: Duration,
    map: Mutex<HashMap<String, (Vec<u8>, Instant)>>,
    lru: Mutex<Vec<String>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl LruCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            default_ttl: ttl,
            map: Mutex::new(HashMap::new()),
            lru: Mutex::new(Vec::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut map = self.map.lock().unwrap();
        let entry = map.get(key)?;
        if entry.1.elapsed() > self.default_ttl {
            map.remove(key);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // 刷新 LRU 位置
        let mut lru = self.lru.lock().unwrap();
        lru.retain(|k| k != key);
        lru.push(key.to_string());
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(entry.0.clone())
    }

    pub fn set(&self, key: &str, value: Vec<u8>) {
        let mut map = self.map.lock().unwrap();
        let mut lru = self.lru.lock().unwrap();
        lru.retain(|k| k != key);
        lru.push(key.to_string());
        map.insert(key.to_string(), (value, Instant::now()));
        while lru.len() > self.capacity {
            if let Some(evict) = lru.first().cloned() {
                lru.remove(0);
                map.remove(&evict);
            }
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.hits.load(Ordering::Relaxed), self.misses.load(Ordering::Relaxed))
    }
}

/// TTL 缓存（L2）
pub struct TtlCache {
    default_ttl: Duration,
    map: DashMap<String, (Vec<u8>, Instant)>,
}

impl TtlCache {
    pub fn new(ttl: Duration) -> Self {
        Self { default_ttl: ttl, map: DashMap::new() }
    }
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let e = self.map.get(key)?;
        if e.value().1.elapsed() > self.default_ttl {
            drop(e);
            self.map.remove(key);
            return None;
        }
        Some(e.value().0.clone())
    }
    pub fn set(&self, key: &str, value: Vec<u8>) {
        self.map.insert(key.to_string(), (value, Instant::now()));
    }
}

/// 多级缓存（读序 L1→L2→源，命中 L2 提升写 L1）
pub struct MultiLevelCache {
    l1: LruCache,
    l2: TtlCache,
}

impl MultiLevelCache {
    pub fn new(l1_capacity: usize, l1_ttl: Duration, l2_ttl: Duration) -> Self {
        Self {
            l1: LruCache::new(l1_capacity, l1_ttl),
            l2: TtlCache::new(l2_ttl),
        }
    }
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        if let Some(v) = self.l1.get(key) {
            return Some(v);
        }
        if let Some(v) = self.l2.get(key) {
            self.l1.set(key, v.clone());
            return Some(v);
        }
        None
    }
    pub fn set(&self, key: &str, value: Vec<u8>) {
        self.l1.set(key, value.clone());
        self.l2.set(key, value);
    }
    pub fn stats(&self) -> (u64, u64) {
        self.l1.stats()
    }
}

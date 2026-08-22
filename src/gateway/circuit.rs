//! 模型级熔断器：CLOSED → OPEN → HALF_OPEN → CLOSED
//! 与 Go 版 internal/gateway/circuit/breaker.go 对齐

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::constants::{
    CB_FAILURE_THRESHOLD_5XX, CB_HALF_OPEN_MAX_ATTEMPTS, CB_OPEN_DURATION_SECS,
    CB_WINDOW_DURATION_SECS, MAX_JSON_DEPTH, MAX_REQUEST_BODY_SIZE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Closed,
    Open,
    HalfOpen,
}

struct ModelBreaker {
    state: State,
    fail429: u32,
    fail5xx: u32,
    window_start: Instant,
    open_until: Instant,
    half_open_attempts: u32,
}

impl ModelBreaker {
    fn new() -> Self {
        Self {
            state: State::Closed,
            fail429: 0,
            fail5xx: 0,
            window_start: Instant::now(),
            open_until: Instant::now(),
            half_open_attempts: 0,
        }
    }
}

#[derive(Clone)]
pub struct CircuitBreaker {
    breakers: Arc<DashMap<String, ModelBreaker>>,
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self { breakers: Arc::new(DashMap::new()) }
    }

    /// 请求是否允许（OPEN 到期自动转 HALF_OPEN 放行探测）
    pub fn can_request(&self, model: &str) -> bool {
        let mut b = self.breakers.entry(model.to_string()).or_insert_with(ModelBreaker::new);
        match b.state {
            State::Closed => true,
            State::Open => {
                if Instant::now() >= b.open_until {
                    b.state = State::HalfOpen;
                    b.half_open_attempts = 1;
                    true
                } else {
                    false
                }
            }
            State::HalfOpen => {
                if b.half_open_attempts < CB_HALF_OPEN_MAX_ATTEMPTS {
                    b.half_open_attempts += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn record_success(&self, model: &str) {
        if let Some(mut b) = self.breakers.get_mut(model) {
            if b.state == State::HalfOpen {
                b.state = State::Closed;
                b.fail429 = 0;
                b.fail5xx = 0;
                b.half_open_attempts = 0;
            }
        }
    }

    pub fn record_failure(&self, model: &str, status: u16) {
        let mut b = self.breakers.entry(model.to_string()).or_insert_with(ModelBreaker::new);
        match b.state {
            State::HalfOpen => {
                b.state = State::Open;
                b.open_until = Instant::now() + Duration::from_secs(CB_OPEN_DURATION_SECS);
            }
            State::Closed => {
                let now = Instant::now();
                if now.duration_since(b.window_start) > Duration::from_secs(CB_WINDOW_DURATION_SECS) {
                    // 窗口过期重置
                    b.fail429 = 0;
                    b.fail5xx = 0;
                    b.window_start = now;
                }
                match status {
                    // 429 为上游限流：由调度器 429 分级冷却机制处理（换 key），不触发模型级熔断，
                    // 避免高频模型因真实 429 反复 OPEN→HALF_OPEN 死循环导致持续 503
                    429 => {}
                    // 连接错误/超时：瞬态网络问题，由调度器 conn_err 冷却处理，不熔断
                    0 => {}
                    500..=599 => b.fail5xx += 1,
                    _ => {}
                }
                if b.fail5xx >= CB_FAILURE_THRESHOLD_5XX {
                    b.state = State::Open;
                    b.open_until = Instant::now() + Duration::from_secs(CB_OPEN_DURATION_SECS);
                }
            }
            State::Open => {}
        }
    }

    /// 请求体安全校验：>10MB 或 JSON 嵌套 >20 层拒绝
    pub fn validate_request_safety(&self, body: &[u8]) -> Result<(), String> {
        if body.len() > MAX_REQUEST_BODY_SIZE {
            return Err(format!(
                "request body too large: {}MB > {}MB",
                body.len() / 1024 / 1024,
                MAX_REQUEST_BODY_SIZE / 1024 / 1024
            ));
        }
        if max_json_depth(body).unwrap_or(0) > MAX_JSON_DEPTH {
            return Err("json nesting too deep".into());
        }
        Ok(())
    }

    /// 打开中的熔断器数量（监控用）
    pub fn open_count(&self) -> u64 {
        let mut n = 0u64;
        for b in self.breakers.iter() {
            if b.state == State::Open {
                n += 1;
            }
        }
        n
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

/// 计算 JSON 最大嵌套深度
fn max_json_depth(body: &[u8]) -> Option<usize> {
    let mut depth = 0usize;
    let mut max = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &c in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    max = depth;
                }
            }
            b'}' | b']' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            _ => {}
        }
    }
    Some(max)
}

// 保持 AtomicU64 引用（模型指标用）
pub struct _KeepAlive(pub AtomicU64);

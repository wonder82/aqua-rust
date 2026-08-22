//! 账号池：健康状态 / 冷却 / 节流 / 空闲最久优先 / 登录节流

use crate::config::AccountCfg;
use crate::ds::{DsClient, SessionInfo};
use crate::humanize::backoff;
use anyhow::{anyhow, Result};
use rand::Rng;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const ST_IDLE: u8 = 0;
pub const ST_BUSY: u8 = 1;
pub const ST_ERROR: u8 = 2;
pub const ST_INVALID: u8 = 3;
pub const MAX_ERROR_COUNT: u8 = 3;

/// 渐进式冷却：首次 2h → 第2次 6h → 第3次+ 24h
fn progressive_cooldown(muted_count: u8, rng: &mut impl rand::Rng) -> i64 {
    match muted_count {
        1 => 2 * 3600 + rng.gen_range(0..1800),   // 2h-2.5h
        2 => 6 * 3600 + rng.gen_range(0..3600),   // 6h-7h
        _ => 24 * 3600 + rng.gen_range(0..7200),  // 24h-26h
    }
}

/// 单个账号运行态
pub struct Account {
    pub cfg: AccountCfg,
    state: AtomicU8,
    /// 会话 token（Sticky，进程内存持久；重启后重新登录）
    token: Mutex<Option<Arc<str>>>,
    /// 最近释放时间（选号：空闲最久优先）
    last_released: AtomicU64,
    /// 上次使用时间（单账号最小间隔节流）
    last_used: Mutex<Instant>,
    /// 冷却截止
    cooldown_until: Mutex<Instant>,
    /// 上次登录时间（登录节流）
    last_login: Mutex<Instant>,
    error_count: AtomicU8,
    /// mute 累计次数（渐进式冷却）
    muted_count: AtomicU8,
    /// 登录次数（统计/日志）
    pub login_count: AtomicU64,
}

impl Account {
    fn new(cfg: AccountCfg) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            state: AtomicU8::new(ST_IDLE),
            token: Mutex::new(None),
            last_released: AtomicU64::new(0),
            last_used: Mutex::new(Instant::now() - std::time::Duration::from_secs(3600)),
            cooldown_until: Mutex::new(Instant::now()),
            last_login: Mutex::new(Instant::now() - std::time::Duration::from_secs(3600)),
            error_count: AtomicU8::new(0),
            muted_count: AtomicU8::new(0),
            login_count: AtomicU64::new(0),
        })
    }

    pub fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    pub fn token(&self) -> Option<String> {
        self.token.lock().unwrap().as_ref().map(|t| t.to_string())
    }

    fn set_token(&self, t: String) {
        *self.token.lock().unwrap() = Some(Arc::from(t));
    }

    fn in_cooldown(&self, now: Instant) -> bool {
        *self.cooldown_until.lock().unwrap() > now
    }

    fn cooldown(&self, secs: u64) {
        *self.cooldown_until.lock().unwrap() = Instant::now() + std::time::Duration::from_secs(secs);
    }

    /// 单账号最小间隔是否满足（min + 本轮随机抖动）
    fn interval_ok(&self, now: Instant, throttle: u64) -> bool {
        now.duration_since(*self.last_used.lock().unwrap()).as_secs() >= throttle
    }
}

/// 账号池
pub struct AccountPool {
    pub accounts: Vec<Arc<Account>>,
    min_interval: u64,
    jitter: u64,
    login_min_interval: u64,
    auto_delete: bool,
}

/// 获取到的账号占用 guard（Drop 时释放回 Idle）
pub struct AccountGuard {
    pub account: Arc<Account>,
    pool: Arc<AccountPool>,
}

impl Drop for AccountGuard {
    fn drop(&mut self) {
        self.pool.release(&self.account);
    }
}

impl AccountPool {
    pub fn new(cfgs: Vec<AccountCfg>, min_interval: u64, jitter: u64, login_min_interval: u64, auto_delete: bool) -> Arc<Self> {
        let accounts = cfgs
            .into_iter()
            .filter(|c| c.enabled)
            .map(Account::new)
            .collect::<Vec<_>>();
        Arc::new(Self {
            accounts,
            min_interval,
            jitter,
            login_min_interval,
            auto_delete,
        })
    }

    pub fn enabled_count(&self) -> usize {
        self.accounts.iter().filter(|a| a.state() != ST_INVALID).count()
    }

    /// 空闲最久优先选号：Idle + 未冷却 + 节流满足；等待最接近可用的账号
    pub async fn acquire(self: &Arc<Self>) -> Result<AccountGuard> {
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let now = Instant::now();
            // 自愈检查：冷却过期的错误账号恢复为 Idle
            for a in &self.accounts {
                self.heal_if_cooled(a);
            }
            // 本轮随机节律 = min_interval + jitter（拟人化，避免固定节拍）
            let throttle = {
                let mut rng = rand::thread_rng();
                self.min_interval + rng.gen_range(0..=self.jitter)
            };
            // 收集候选：Idle 且未冷却
            let mut candidates: Vec<(i64, Arc<Account>)> = self
                .accounts
                .iter()
                .filter(|a| a.state() == ST_IDLE && !a.in_cooldown(now))
                .map(|a| (i64::MAX - a.last_released.load(Ordering::Acquire) as i64, a.clone()))
                .collect();
            candidates.sort_by(|a, b| b.0.cmp(&a.0)); // 空闲最久（last_released 最小）优先

            // 找出满足节流或等待最短的
            let mut best: Option<(u64, Arc<Account>)> = None;
            for (_, a) in &candidates {
                if a.interval_ok(now, throttle) {
                    best = Some((0, a.clone()));
                    break;
                }
                let wait = throttle.saturating_sub(now.duration_since(*a.last_used.lock().unwrap()).as_secs());
                if best.as_ref().map(|(w, _)| wait < *w).unwrap_or(true) {
                    best = Some((wait, a.clone()));
                }
            }
            match best {
                Some((wait, acc)) => {
                    if wait > 0 {
                        if Instant::now() + std::time::Duration::from_secs(wait) > deadline {
                            return Err(anyhow!("acu pool busy: no account ready within 30s"));
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                    }
                    // CAS Idle -> Busy
                    if acc.state.compare_exchange(ST_IDLE, ST_BUSY, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                        *acc.last_used.lock().unwrap() = Instant::now();
                        return Ok(AccountGuard { account: acc, pool: self.clone() });
                    }
                    // 竞争失败重试
                }
                None => {
                    if Instant::now() > deadline {
                        return Err(anyhow!("acu pool empty: no idle account"));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    }

    fn release(&self, acc: &Account) {
        if acc.state() == ST_BUSY {
            acc.state.store(ST_IDLE, Ordering::Release);
            acc.last_released.store(now_millis(), Ordering::Release);
        }
    }

    /// 登录节流 + 登录；失败进入冷却
    pub async fn ensure_login(&self, client: &DsClient, acc: &Account) -> Result<SessionInfo> {
        // 已有 token 直接复用（Sticky Session 进程内保持）
        if let Some(t) = acc.token() {
            return Ok(SessionInfo { token: t, user_id: String::new() });
        }
        // 登录节流
        let wait = self
            .login_min_interval
            .saturating_sub(Instant::now().duration_since(*acc.last_login.lock().unwrap()).as_secs());
        if wait > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        }
        *acc.last_login.lock().unwrap() = Instant::now();
        let result = client.login(&acc.cfg.email, &acc.cfg.password, acc.cfg.ua.as_deref()).await;
        match result {
            Ok(s) => {
                acc.set_token(s.token.clone());
                acc.login_count.fetch_add(1, Ordering::Relaxed);
                // 冷却期登录成功 → 清冷却
                acc.cooldown(0);
                acc.error_count.store(0, Ordering::Relaxed);
                Ok(s)
            }
            Err(e) => {
                let e_str = e.to_string();
                let n = acc.error_count.fetch_add(1, Ordering::Relaxed) + 1;
                acc.state.store(ST_ERROR, Ordering::Release);
                // 账号被官方风控（muted）：24h 长冷却，不计入致命失败次数（可能是批量风控）
                if e_str.to_lowercase().contains("muted") {
                    acc.cooldown(24 * 3600);
                    return Err(anyhow!("account {name} muted: {e_str}", name = acc.cfg.name));
                }
                if n >= MAX_ERROR_COUNT {
                    acc.state.store(ST_INVALID, Ordering::Release);
                    return Err(anyhow!("account {name} invalid after {n} login failures: {e}", name = acc.cfg.name));
                }
                let secs = backoff(n as u32, 30).as_secs().min(3600);
                acc.cooldown(secs);
                Err(anyhow!("account {name} login failed (err#{n}): {e}", name = acc.cfg.name))
            }
        }
    }

    pub fn mark_error(&self, acc: &Account) {
        if acc.state() != ST_BUSY {
            return;
        }
        acc.state.store(ST_ERROR, Ordering::Release);
        let n = acc.error_count.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= MAX_ERROR_COUNT {
            acc.state.store(ST_INVALID, Ordering::Release);
            return;
        }
        // 随机 5-15min 短冷却（muted 类由上层 24h 冷却覆盖）
        let mut rng = rand::thread_rng();
        let secs = 300 + rng.gen_range(0..600);
        acc.cooldown(secs);
    }

    /// muted 检测 → 渐进式冷却（首次 2h，重复 mute 递增到 24h）
    /// 上游给出解禁时间戳则冷却到解禁后 30 分钟余量
    pub fn mark_muted(&self, acc: &Account, mute_until_unix: Option<i64>) {
        acc.state.store(ST_ERROR, Ordering::Release);
        let muted_count = acc.muted_count.fetch_add(1, Ordering::Relaxed) + 1;
        let mut rng = rand::thread_rng();
        let secs = match mute_until_unix {
            Some(ts) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let remain = ts - now;
                if remain > 0 { (remain + 1800).min(3 * 24 * 3600) } else { progressive_cooldown(muted_count, &mut rng) }
            }
            None => progressive_cooldown(muted_count, &mut rng),
        };
        acc.cooldown(secs.max(300) as u64);
        tracing::warn!(account = %acc.cfg.name, muted_count, "account muted, cooldown {}s (mute #{})", secs, muted_count);
    }

    /// 冷却过期后自动恢复：清除错误计数，账号回到 Idle
    pub fn heal_if_cooled(&self, acc: &Account) {
        let now = Instant::now();
        if !acc.in_cooldown(now) && acc.state.load(Ordering::Acquire) == ST_ERROR {
            acc.state.store(ST_IDLE, Ordering::Release);
            acc.error_count.store(0, Ordering::Relaxed);
            acc.muted_count.store(0, Ordering::Relaxed);
            tracing::info!(account = %acc.cfg.name, "account healed: cooldown expired, restored to idle");
        }
    }

    pub fn auto_delete(&self) -> bool {
        self.auto_delete
    }

    /// 瞬态失败（限流/空响应/上游抖动）：短冷却，不累计致命失败次数（避免毒化账号池）
    /// 账号 Drop 后自然回 Idle，acquire 因 cooldown 自动跳过，到期即可用。
    pub fn mark_transient(&self, acc: &Account, max_secs: u64) {
        let mut rng = rand::thread_rng();
        let secs = 20 + rng.gen_range(0..max_secs.max(1));
        acc.cooldown(secs);
        tracing::debug!(account = %acc.cfg.name, "transient throttle, cooldown {}s", secs);
    }

    /// token 失效：清除进程内 token，下次请求自动重新登录
    pub fn invalidate_token(&self, acc: &Account) {
        *acc.token.lock().unwrap() = None;
        tracing::debug!(account = %acc.cfg.name, "token invalidated, next request will re-login");
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}


//! AQUA Platform Rust — 单二进制双服务入口（平台 :8000 + 网关 :8001）
//! 与 Go 版 cmd/server/main.go 对齐：共享配置/连接池/调度器，优雅关闭 30s

mod appstate;
mod config;
mod constants;
mod db;
mod error;
mod gateway;
mod model;
mod platform;
mod security;

use std::sync::Arc;
use std::time::Duration;

use axum::response::Response;
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::{info, warn};

use appstate::AppState;
use config::Config;

/// 极致内存优化（K3）：全局分配器使用 mimalloc（碎片低、峰值 RSS 小）
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    // tokio 运行时：4 worker（8 核机器收敛线程栈占用；并发仍充足）
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to build tokio runtime: {e}");
            std::process::exit(1);
        }
    };
    rt.block_on(run());
}

async fn run() {
    // ===== 加载配置 =====
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    // ===== 结构化日志（JSON）=====
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .json()
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("set tracing subscriber");
    info!(
        version = "0.1.0",
        platform_port = %cfg.server.platform_port,
        gateway_port = %cfg.server.gateway_port,
        "starting AQUA Server (single binary, dual service)"
    );

    // ===== 初始化数据库 =====
    let pool = match db::new_pool(&cfg).await {
        Ok(p) => p,
        Err(e) => {
            warn!("db init failed: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = db::init_schema(&pool).await {
        warn!("schema check: {e}");
        std::process::exit(1);
    }
    if let Err(e) = db::seed_defaults(&pool, &cfg).await {
        warn!("seed defaults: {e}");
    }
    let platform_encrypt_key = match cfg.decode_platform_encrypt_key() {
        Ok(k) => k,
        Err(e) => {
            warn!("decode encrypt key failed: {e}");
            std::process::exit(1);
        }
    };
    // 网关主密钥：DB upstream_master_key 优先，回退 PLATFORM_ENCRYPT_KEY（与 Go 版一致）
    let upstream_master_key = load_upstream_master_key(&pool).await.unwrap_or_else(|_| platform_encrypt_key.clone());
    let state = Arc::new(AppState::new(cfg.clone(), pool, upstream_master_key, platform_encrypt_key));
    // 加载可信客户端白名单 + 刷新 IP 封禁缓存
    state.load_trusted_clients().await;
    state.ip_monitor.refresh_blocked_cache().await;
    // 恢复网关维护模式状态
    gateway::handler::admin::init_from_db(&state).await;
    info!("security engines initialized (ip_monitor / anomaly_guard / trusted_clients)");
    // 后台任务：IP 封禁缓存周期刷新
    {
        let ipm = state.ip_monitor.clone();
        tokio::spawn(async move {
            gateway::detect::run_ip_monitor_bg(ipm).await;
        });
    }
    // 后台任务：密钥调度器周期清理 + 密钥池热更新（DB 变更 ≤30s 生效，不中断服务）
    {
        let sched = state.scheduler.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                sched.run_background_tasks().await;
            }
        });
    }
    // 后台任务：模型健康巡检（自动下架故障模型，5 分钟粒度）+ force_stream 配置刷新
    {
        let mh = state.model_health.clone();
        let fs = state.force_stream.clone();
        let pool = state.pool.clone();
        // 启动时立即初始化动态开关（避免热更后 60s 空窗期配置未生效）
        {
            let v: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='force_stream_default'")
                .fetch_optional(&pool).await.ok().flatten();
            fs.store(v.as_deref() == Some("true"), std::sync::atomic::Ordering::Relaxed);
            let v2: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='special_model_suspended'")
                .fetch_optional(&pool).await.ok().flatten();
            crate::model::catalog::set_special_suspended(v2.as_deref() == Some("true"));
            let v3: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='special_model_call_allowed'")
                .fetch_optional(&pool).await.ok().flatten();
            crate::model::catalog::set_special_call_allowed(v3.as_deref() == Some("true"));
            let v4: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='special_suspended_models'")
                .fetch_optional(&pool).await.ok().flatten();
            crate::model::catalog::set_suspended_models(v4.as_deref());
        }
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                // 刷新强制流式开关（admin_settings.force_stream_default）
                let v: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='force_stream_default'")
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten();
                fs.store(v.as_deref() == Some("true"), std::sync::atomic::Ordering::Relaxed);
                // 刷新特殊专属模型暂停开关（admin_settings.special_model_suspended，true=临时下架）
                let v2: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='special_model_suspended'")
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten();
                crate::model::catalog::set_special_suspended(v2.as_deref() == Some("true"));
                // 刷新特殊专属模型调用开放开关（admin_settings.special_model_call_allowed，true=开放调用）
                let v3: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='special_model_call_allowed'")
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten();
                crate::model::catalog::set_special_call_allowed(v3.as_deref() == Some("true"));
                // 刷新单模型暂停列表（admin_settings.special_suspended_models，JSON 数组）
                let v4: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='special_suspended_models'")
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten();
                crate::model::catalog::set_suspended_models(v4.as_deref());
                // 每 5 次循环（约 5 分钟）执行一次健康巡检
                for _ in 0..5 {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                mh.refresh(&pool).await;
            }
        });
    }
    // 后台任务：上游模型列表同步（以 NIM /v1/models 为权威基准，启动立即 + 每小时）
    {
        let pool = state.pool.clone();
        let master_key = state.upstream_master_key.clone();
        tokio::spawn(async move {
            // 启动立即同步一次（阻塞后续任务启动约 15s，换取模型列表即刻准确）
            crate::model::upstream::sync_upstream_models(&pool, &master_key).await;
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                crate::model::upstream::sync_upstream_models(&pool, &master_key).await;
            }
        });
    }

    // ===== 平台 Router :8000 =====
    let platform_router = build_platform_router(state.clone());
    let platform_addr = format!("0.0.0.0:{}", cfg.server.platform_port);

    // ===== 网关 Router :8001 =====
    let gateway_router = build_gateway_router(state.clone());
    let gateway_addr = format!("0.0.0.0:{}", cfg.server.gateway_port);

    // ===== 启动双服务（SO_REUSEPORT：热更滚动零中断，新实例先接管、旧实例再退出）=====
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(8);
    let mut handles = Vec::new();

    let p_addr = platform_addr.clone();
    let mut rx_platform = shutdown_tx.subscribe();
    handles.push(tokio::spawn(async move {
        let listener = bind_reuse(&p_addr).await.unwrap();
        info!(addr = %p_addr, "platform service listening");
        axum::serve(listener, platform_router)
            .with_graceful_shutdown(async move {
                // 收到关闭信号：停止 accept 新连接，等待在途请求完成
                let _ = rx_platform.recv().await;
            })
            .await
            .unwrap();
    }));

    let g_addr = gateway_addr.clone();
    let mut rx_gateway = shutdown_tx.subscribe();
    handles.push(tokio::spawn(async move {
        let listener = bind_reuse(&g_addr).await.unwrap();
        info!(addr = %g_addr, "gateway service listening");
        axum::serve(listener, gateway_router)
            .with_graceful_shutdown(async move {
                let _ = rx_gateway.recv().await;
            })
            .await
            .unwrap();
    }));

    // ===== 信号处理（优雅关闭：drain 在途请求，最多 30s）=====
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
    info!("received shutdown signal, draining in-flight requests (max 30s)");
    let _ = shutdown_tx.send(());
    let timeout_result = tokio::time::timeout(Duration::from_secs(30), async {
        for h in handles {
            let _ = h.await;
        }
    }).await;
    // 在途长连接（keep-alive / SSE 流式）可能一直不结束，超时后强制退出，
    // 避免 systemd 等待到 TimeoutStopSec 再 SIGKILL（导致恢复被拖慢/标记 timeout 失败）
    if timeout_result.is_err() {
        warn!("graceful drain timed out (long-lived connections), force exiting");
        std::process::exit(0);
    }
    info!("AQUA Server stopped");
}

/// 请求日志自动清理：分批删除过期数据，避免长事务锁表
/// - request_logs（网关日志）：2xx 成功保留 30 天，其余状态（4xx/5xx 等）保留 90 天
/// - pf_request_logs（平台日志）：status='success' 保留 30 天，其余保留 90 天
async fn cleanup_old_logs(pool: &sqlx::PgPool) {
    // 1. request_logs 非错误数据（2xx）
    batch_delete_logs(pool, "request_logs", "status_code BETWEEN 200 AND 299", "30 days").await;
    // 2. request_logs 错误数据（非 2xx）
    batch_delete_logs(pool, "request_logs", "(status_code < 200 OR status_code > 299)", "90 days").await;
    // 3. pf_request_logs 成功数据
    batch_delete_logs(pool, "pf_request_logs", "status = 'success'", "30 days").await;
    // 4. pf_request_logs 错误数据
    batch_delete_logs(pool, "pf_request_logs", "status != 'success'", "90 days").await;
}

/// 分批删除（每批 5000 行，间隔 50ms，避免长锁；返回删除总数）
async fn batch_delete_logs(pool: &sqlx::PgPool, table: &str, cond: &str, keep: &str) -> u64 {
    let mut total: u64 = 0;
    loop {
        let q = format!(
            "DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {cond} \
             AND created_at < now() - interval '{keep}' LIMIT 5000)"
        );
        match sqlx::query(&q).execute(pool).await {
            Ok(r) => {
                let n = r.rows_affected();
                if n == 0 {
                    break;
                }
                total += n;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                warn!("cleanup {table} ({cond}) failed: {e}");
                break;
            }
        }
    }
    if total > 0 {
        info!("cleanup {table} removed {total} rows (older than {keep}, condition: {cond})");
    }
    total
}

/// SO_REUSEPORT 监听：热更期间新旧实例可共享同一端口（Linux）
async fn bind_reuse(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e: std::net::AddrParseError| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    // SO_REUSEPORT：允许新实例与旧实例在滚动更新期间共享端口
    set_so_reuse_port(&socket)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

/// 通过 libc 设置 SO_REUSEPORT（socket2 0.5 部分版本不导出该方法）
fn set_so_reuse_port(sock: &socket2::Socket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// CORS 中间件（复用网关导出的配置）
fn cors_layer(cfg: &Config) -> CorsLayer {
    let has_wildcard = cfg.cors_origins.iter().any(|o| o == "*");
    if has_wildcard {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let origins: Vec<axum::http::HeaderValue> = cfg
            .cors_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(Any)
            .allow_headers(Any)
    }
}

/// HTML 页面禁止浏览器缓存（避免旧版/404 页面被长期缓存导致"页面不显示"）
async fn no_cache_html(request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next) -> Response {
    let mut response = next.run(request).await;
    let is_html = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false);
    if is_html {
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        );
    }
    response
}

/// 安全响应头中间件（防点击劫持 / MIME 嗅探 / 信息泄露，2026-08 安全加固）
async fn security_headers(request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Frame-Options", axum::http::HeaderValue::from_static("DENY"));
    headers.insert("X-Content-Type-Options", axum::http::HeaderValue::from_static("nosniff"));
    headers.insert("Referrer-Policy", axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert("Permissions-Policy", axum::http::HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"));
    headers.insert("X-XSS-Protection", axum::http::HeaderValue::from_static("1; mode=block"));
    response
}

/// 平台 Router（页面 + 静态 + API）
fn build_platform_router(state: Arc<AppState>) -> Router {
    use axum::routing::{delete, get, get_service, patch, post, put};
    use tower_http::services::ServeFile;
    use crate::platform::handler as ph;
    let cors = cors_layer(&state.cfg);
    let html = |f: &str| get_service(ServeFile::new(format!("web/platform/static/{f}")));
    Router::new()
        // ===== 基础 =====
        .route("/healthz", get(ph::public::healthz))
        .route("/robots.txt", get(ph::public::robots_txt))
        .route("/sitemap.xml", get(ph::public::sitemap))
        .route("/favicon.ico", get(ph::public::favicon))
        .route("/", get(ph::public::index))
        // ===== 静态页面 =====
        .route("/login", html("login.html"))
        .route("/register", html("register.html"))
        .route("/reset-password", html("reset-password.html"))
        .route("/models", html("models.html"))
        .route("/docs", html("docs.html"))
        .route("/quick-start", html("quick-start.html"))
        .route("/qq-group", html("qq-group.html"))
        .route("/sponsor", html("sponsor.html"))
        .route("/capabilities", html("capabilities.html"))
        // ⚠️ 2026-08-11 QQ 群联系通道已废弃，页面与路由一并移除
        // .route("/qq-groups", html("qq-groups.html"))
        .route("/console", html("console.html"))
        .route("/console/keys", html("keys.html"))

        .route("/console/stats", html("stats.html"))
        .route("/console/logs", html("logs.html"))
        .route("/console/models", html("console-models.html"))
        .route("/console/capabilities", html("console-capabilities.html"))
        .route("/console/capability-detail", html("console-capability-detail.html"))
        .route("/console/metrics", html("console-metrics.html"))
        .route("/console/rank", html("console-rank.html"))
        .route("/console/docs", html("console-docs.html"))
        .route("/console/settings", html("settings.html"))
        .route("/admin", html("admin.html"))
        // ===== 模型列表代理 =====
        .route("/v1/models", get(ph::public::api_models))
        .route("/v1/models/", get(ph::public::api_models))
        .route("/api/v1/models", get(ph::public::api_models))
        .route("/api/v1/models/", get(ph::public::api_models))
        // ===== 认证 =====
        .route("/api/auth/send-code", post(ph::auth::send_code))
        .route("/api/auth/register", post(ph::auth::register))
        .route("/api/auth/login", post(ph::auth::login))
        .route("/api/auth/logout", post(ph::auth::logout))
        .route("/api/auth/reset-password", post(ph::auth::reset_password))
        .route("/api/auth/verify", get(ph::auth::verify))
        // ===== 对话 =====
        // 网页对话功能已下线（2026-08-08）：仅保留模型列表供模型广场/控制台使用
        .route("/api/chat/models", get(ph::chat::models))
        // ===== 用户控制台 =====
        .route("/api/user/profile", get(ph::console::profile))
        .route("/api/user/stats", get(ph::console::stats))
        .route("/api/user/usage-overview", get(ph::console::usage_overview))
        .route("/api/user/concurrency-stats", get(ph::console::concurrency_stats))
        .route("/api/user/usage-limits", get(ph::console::usage_limits))
        .route("/api/user/leaderboard", get(ph::console::leaderboard))
        .route("/api/user/model-usage", get(ph::console::model_usage))
        .route("/api/user/models/status", get(ph::console::models_status))
        .route("/api/user/model-metrics-v2", get(ph::console::model_metrics_v2))
        .route("/api/user/request-logs", get(ph::console::request_logs))
        .route("/api/user/model-capabilities", get(ph::console::model_capabilities))
        .route("/api/user/keys", get(ph::console::list_keys_handler).post(ph::console::create_key_handler))
        .route("/api/user/keys/{id}", delete(ph::console::delete_key).patch(ph::console::update_key))
        .route("/api/user/keys/{id}/reveal", get(ph::console::reveal_key))
        .route("/api/user/keys/{id}/toggle", post(ph::console::toggle_key))
        .route("/api/user/settings", put(ph::console::settings).patch(ph::console::settings))
        .route("/api/user/username", put(ph::console::update_username))
        .route("/api/user/email", post(ph::console::change_email))
        .route("/api/user/delete-account", post(ph::console::delete_account))
        .route("/api/user/system/concurrency", get(ph::console::system_concurrency))
        .route("/api/user/system/health", get(ph::console::system_health))
        .route("/api/user/system/ip-monitor", get(ph::console::system_ip_monitor))
        .route("/api/user/system/ip-monitor/blocked", get(ph::console::system_ip_blocked))
        .route("/api/user/system/ip-monitor/anomalies", get(ph::console::system_ip_anomalies))
        .route("/api/user/system/ip-monitor/unblock", post(ph::console::system_ip_unblock))
        .route("/api/user/system/user-stats", get(ph::console::system_user_stats))
        // ===== 公开 API =====
        .route("/api/public/stats", get(ph::public::public_stats))
        // ⚠️ 2026-08-11 Codex 上游下线：/api/public/acu-usage 已注释（public_acu_usage 同步注释）
        // .route("/api/public/acu-usage", get(ph::public::public_acu_usage))
        .route("/api/public/model-capabilities", get(ph::public::public_model_capabilities))
        // ===== 管理后台 =====
        .route("/api/admin/login", post(ph::admin::login))
        .route("/api/admin/logout", post(ph::admin::logout))
        .route("/api/admin/check", get(ph::admin::check))
        .route("/api/admin/login-logs", get(ph::admin::login_logs))
        .route("/api/admin/users", get(ph::admin::users))
        .route("/api/admin/users/{id}", get(ph::admin::user_detail_handler).delete(ph::admin::delete_user_handler))
        .route("/api/admin/users/{id}/ban", put(ph::admin::ban_user_handler).patch(ph::admin::ban_user_handler))
        .route("/api/admin/users/{id}/unban", put(ph::admin::unban_user_handler).patch(ph::admin::unban_user_handler))
        // ===== 蜜罐 =====
        .route("/.env", get(ph::admin::honeypot_route).post(ph::admin::honeypot_route))
        .route("/.git/config", get(ph::admin::honeypot_route))
        .route("/.git/HEAD", get(ph::admin::honeypot_route))
        .route("/wp-admin", get(ph::admin::honeypot_route))
        .route("/wp-login.php", get(ph::admin::honeypot_route))
        .route("/phpmyadmin", get(ph::admin::honeypot_route))
        .route("/server-status", get(ph::admin::honeypot_route))
        .route("/api/admin/debug", get(ph::admin::honeypot_route))
        .route("/api/admin/config", get(ph::admin::honeypot_route))
        .route("/actuator/env", get(ph::admin::honeypot_route))
        .route("/actuator/health", get(ph::admin::honeypot_route))
        .route("/config/database.yml", get(ph::admin::honeypot_route))
        .route("/gw/admin/system/dump", get(ph::admin::honeypot_route))
        .nest_service("/static", ServeDir::new("web/platform/static"))
        .nest_service("/uploads", ServeDir::new("web/uploads"))
        .with_state(state)
        .layer(cors)
        .layer(axum::middleware::from_fn(no_cache_html))
        .layer(axum::middleware::from_fn(security_headers))
}

/// 网关 Router（公开 API + 健康检查 + 管理控制台）
fn build_gateway_router(state: Arc<AppState>) -> Router {
    use axum::routing::{delete, get, post, put};
    use gateway::handler::{admin, admin_monitoring, public};
    let cors = cors_layer(&state.cfg);
    Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/v1/models", axum::routing::get(public::models_handler))
        .route("/api/v1/models", axum::routing::get(public::models_handler))
        // ⚠️ 2026-08-11 Codex 上游下线：/v1/acu/usage 路由已注释（acu_usage 同步注释）
        // .route("/v1/acu/usage", axum::routing::get(public::acu_usage))
        // .route("/api/v1/acu/usage", axum::routing::get(public::acu_usage))
        .route("/v1/chat/completions", axum::routing::post(public::chat_completions_handler))
        .route("/api/v1/chat/completions", axum::routing::post(public::chat_completions_handler))
        .route("/v1/embeddings", axum::routing::post(public::embeddings_handler))
        .route("/api/v1/embeddings", axum::routing::post(public::embeddings_handler))
        .route("/v1/messages", axum::routing::post(public::multi_protocol_handler))
        .route("/api/v1/messages", axum::routing::post(public::multi_protocol_handler))
        .route("/v1/messages/count_tokens", axum::routing::post(public::multi_protocol_handler))
        .route("/v1/responses", axum::routing::post(public::multi_protocol_handler))
        .route("/api/v1/responses", axum::routing::post(public::multi_protocol_handler))
        .route("/v1beta/models/{*rest}", axum::routing::post(public::multi_protocol_handler))
        // ===== 网关管理后台 /gw/admin/* =====
        .route("/gw/admin/login", post(admin::login))
        .route("/gw/admin/dashboard", get(admin::dashboard))
        .route("/gw/admin/upstreams", get(admin::upstreams_list).post(admin::upstreams_create))
        .route("/gw/admin/upstreams/{id}", get(admin::get_upstream).put(admin::update_upstream).delete(admin::delete_upstream))
        .route("/gw/admin/upstreams/{id}/reveal", get(admin::reveal_upstream))
        .route("/gw/admin/upstreams/{id}/unfreeze", post(admin::unfreeze_upstream))
        .route("/gw/admin/clients", get(admin::clients).post(admin::create_client))
        .route("/gw/admin/clients/{id}", get(admin::get_client).put(admin::update_client).delete(admin::delete_client))
        .route("/gw/admin/clients/{id}/keys", get(admin::list_client_keys).post(admin::create_client_key))
        .route("/gw/admin/clients/{id}/keys/{kid}", delete(admin::delete_client_key))
        .route("/gw/admin/clients/{id}/keys/{kid}/reveal", get(admin::reveal_client_key))
        .route("/gw/admin/request-logs", get(admin_monitoring::request_logs))
        .route("/gw/admin/request-logs/{id}", get(admin_monitoring::get_request_log))
        .route("/gw/admin/request-logs/cleanup", delete(admin_monitoring::cleanup_request_logs))
        .route("/gw/admin/request-logs-stats/summary", get(admin_monitoring::request_logs_summary))
        .route("/gw/admin/error-stats", get(admin_monitoring::error_stats))
        .route("/gw/admin/stats/request-trend", get(admin_monitoring::request_trend))
        .route("/gw/admin/stats/error-analysis", get(admin_monitoring::error_analysis))
        .route("/gw/admin/stats/latency-distribution", get(admin_monitoring::latency_distribution))
        .route("/gw/admin/active-errors", get(admin_monitoring::active_errors))
        .route("/gw/admin/error-codes", get(admin_monitoring::error_codes))
        .route("/gw/admin/global-status", get(admin_monitoring::global_status))
        .route("/gw/admin/system/health", get(admin_monitoring::system_health))
        .route("/gw/admin/system/ip-monitor", get(admin_monitoring::ip_monitor))
        .route("/gw/admin/system/ip-monitor/blocked", get(admin_monitoring::blocked_ips))
        .route("/gw/admin/system/ip-monitor/unblock", post(admin_monitoring::unblock_ip))
        .route("/gw/admin/circuit-breakers", get(admin_monitoring::circuit_breakers))
        .route("/gw/admin/circuit-breakers/reset", post(admin_monitoring::reset_circuit_breakers))
        .route("/gw/admin/anomaly/stats", get(admin_monitoring::anomaly_stats))
        .route("/gw/admin/settings", get(admin_monitoring::settings_get).post(admin_monitoring::settings_update))
        .route("/gw/admin/maintenance", post(admin_monitoring::maintenance))
        .route("/gw/admin/audit-logs", get(admin_monitoring::audit_logs))
        .route("/gw/admin/mail/list", get(admin_monitoring::mail_list))
        .route("/gw/admin/mail/detail", get(admin_monitoring::mail_detail))
        .route("/", axum::routing::get(gw_console))
        .route("/console", axum::routing::get(gw_console))
        .route("/admin", axum::routing::get(gw_console))
        .nest_service("/static", ServeDir::new("web/gateway/static"))
        .with_state(state)
        .layer(cors)
        .layer(axum::middleware::from_fn(no_cache_html))
        .layer(axum::middleware::from_fn(security_headers))
}

/// 网关控制台页面（console.html）
async fn gw_console() -> Response {
    crate::platform::handler::public::serve_file("web/gateway/static/console.html", "text/html; charset=utf-8").await
}

/// 健康检查
async fn healthz() -> &'static str {
    "OK"
}

/// 从 DB 读取 upstream_master_key（base64 解码）
async fn load_upstream_master_key(pool: &sqlx::PgPool) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let b64: String = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key = 'upstream_master_key'")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("read upstream_master_key: {e}"))?;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64.trim()))
        .map_err(|e| format!("decode upstream_master_key: {e}"))
}


//! AQUA Platform Rust 鈥?鍗曚簩杩涘埗鍙屾湇鍔″叆鍙ｏ紙骞冲彴 :8000 + 缃戝叧 :8001锛?//! 涓?Go 鐗?cmd/server/main.go 瀵归綈锛氬叡浜厤缃?杩炴帴姹?璋冨害鍣紝浼橀泤鍏抽棴 30s

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

/// 鏋佽嚧鍐呭瓨浼樺寲锛圞3锛夛細鍏ㄥ眬鍒嗛厤鍣ㄤ娇鐢?mimalloc锛堢鐗囦綆銆佸嘲鍊?RSS 灏忥級
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    // tokio 杩愯鏃讹細4 worker锛? 鏍告満鍣ㄦ敹鏁涚嚎绋嬫爤鍗犵敤锛涘苟鍙戜粛鍏呰冻锛?    let rt = match tokio::runtime::Builder::new_multi_thread()
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
    // ===== 鍔犺浇閰嶇疆 =====
    let cfg = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    // ===== 缁撴瀯鍖栨棩蹇楋紙JSON锛?====
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

    // ===== 鍒濆鍖栨暟鎹簱 =====
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
    // 缃戝叧涓诲瘑閽ワ細DB upstream_master_key 浼樺厛锛屽洖閫€ PLATFORM_ENCRYPT_KEY锛堜笌 Go 鐗堜竴鑷达級
    let upstream_master_key = load_upstream_master_key(&pool).await.unwrap_or_else(|_| platform_encrypt_key.clone());
    let state = Arc::new(AppState::new(cfg.clone(), pool, upstream_master_key, platform_encrypt_key));
    // 鍔犺浇鍙俊瀹㈡埛绔櫧鍚嶅崟 + 鍒锋柊 IP 灏佺缂撳瓨
    state.load_trusted_clients().await;
    state.ip_monitor.refresh_blocked_cache().await;
    // 鎭㈠缃戝叧缁存姢妯″紡鐘舵€?    gateway::handler::admin::init_from_db(&state).await;
    info!("security engines initialized (ip_monitor / anomaly_guard / trusted_clients)");
    // 鍚庡彴浠诲姟锛欼P 灏佺缂撳瓨鍛ㄦ湡鍒锋柊
    {
        let ipm = state.ip_monitor.clone();
        tokio::spawn(async move {
            gateway::detect::run_ip_monitor_bg(ipm).await;
        });
    }
    // 鍚庡彴浠诲姟锛氬瘑閽ヨ皟搴﹀櫒鍛ㄦ湡娓呯悊 + 瀵嗛挜姹犵儹鏇存柊锛圖B 鍙樻洿 鈮?0s 鐢熸晥锛屼笉涓柇鏈嶅姟锛?    {
        let sched = state.scheduler.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                sched.run_background_tasks().await;
            }
        });
    }
    // 鍚庡彴浠诲姟锛氭ā鍨嬪仴搴峰贰妫€锛堣嚜鍔ㄤ笅鏋舵晠闅滄ā鍨嬶紝5 鍒嗛挓绮掑害锛? force_stream 閰嶇疆鍒锋柊
    {
        let mh = state.model_health.clone();
        let fs = state.force_stream.clone();
        let pool = state.pool.clone();
        // 鍚姩鏃剁珛鍗冲垵濮嬪寲鍔ㄦ€佸紑鍏筹紙閬垮厤鐑洿鍚?60s 绌虹獥鏈熼厤缃湭鐢熸晥锛?        {
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
                // 鍒锋柊寮哄埗娴佸紡寮€鍏筹紙admin_settings.force_stream_default锛?                let v: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='force_stream_default'")
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten();
                fs.store(v.as_deref() == Some("true"), std::sync::atomic::Ordering::Relaxed);
                // 鍒锋柊鐗规畩涓撳睘妯″瀷鏆傚仠寮€鍏筹紙admin_settings.special_model_suspended锛宼rue=涓存椂涓嬫灦锛?                let v2: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='special_model_suspended'")
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten();
                crate::model::catalog::set_special_suspended(v2.as_deref() == Some("true"));
                // 鍒锋柊鐗规畩涓撳睘妯″瀷璋冪敤寮€鏀惧紑鍏筹紙admin_settings.special_model_call_allowed锛宼rue=寮€鏀捐皟鐢級
                let v3: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='special_model_call_allowed'")
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten();
                crate::model::catalog::set_special_call_allowed(v3.as_deref() == Some("true"));
                // 鍒锋柊鍗曟ā鍨嬫殏鍋滃垪琛紙admin_settings.special_suspended_models锛孞SON 鏁扮粍锛?                let v4: Option<String> = sqlx::query_scalar("SELECT value FROM admin_settings WHERE key='special_suspended_models'")
                    .fetch_optional(&pool)
                    .await
                    .ok()
                    .flatten();
                crate::model::catalog::set_suspended_models(v4.as_deref());
                // 姣?5 娆″惊鐜紙绾?5 鍒嗛挓锛夋墽琛屼竴娆″仴搴峰贰妫€
                for _ in 0..5 {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                mh.refresh(&pool).await;
            }
        });
    }
    // 鍚庡彴浠诲姟锛氫笂娓告ā鍨嬪垪琛ㄥ悓姝ワ紙浠?NIM /v1/models 涓烘潈濞佸熀鍑嗭紝鍚姩绔嬪嵆 + 姣忓皬鏃讹級
    {
        let pool = state.pool.clone();
        let master_key = state.upstream_master_key.clone();
        tokio::spawn(async move {
            // 鍚姩绔嬪嵆鍚屾涓€娆★紙闃诲鍚庣画浠诲姟鍚姩绾?15s锛屾崲鍙栨ā鍨嬪垪琛ㄥ嵆鍒诲噯纭級
            crate::model::upstream::sync_upstream_models(&pool, &master_key).await;
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                crate::model::upstream::sync_upstream_models(&pool, &master_key).await;
            }
        });
    }

    // ===== 骞冲彴 Router :8000 =====
    let platform_router = build_platform_router(state.clone());
    let platform_addr = format!("0.0.0.0:{}", cfg.server.platform_port);

    // ===== 缃戝叧 Router :8001 =====
    let gateway_router = build_gateway_router(state.clone());
    let gateway_addr = format!("0.0.0.0:{}", cfg.server.gateway_port);

    // ===== 鍚姩鍙屾湇鍔★紙SO_REUSEPORT锛氱儹鏇存粴鍔ㄩ浂涓柇锛屾柊瀹炰緥鍏堟帴绠°€佹棫瀹炰緥鍐嶉€€鍑猴級=====
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(8);
    let mut handles = Vec::new();

    let p_addr = platform_addr.clone();
    let mut rx_platform = shutdown_tx.subscribe();
    handles.push(tokio::spawn(async move {
        let listener = bind_reuse(&p_addr).await.unwrap();
        info!(addr = %p_addr, "platform service listening");
        axum::serve(listener, platform_router)
            .with_graceful_shutdown(async move {
                // 鏀跺埌鍏抽棴淇″彿锛氬仠姝?accept 鏂拌繛鎺ワ紝绛夊緟鍦ㄩ€旇姹傚畬鎴?                let _ = rx_platform.recv().await;
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

    // ===== 淇″彿澶勭悊锛堜紭闆呭叧闂細drain 鍦ㄩ€旇姹傦紝鏈€澶?30s锛?====
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
    // 鍦ㄩ€旈暱杩炴帴锛坘eep-alive / SSE 娴佸紡锛夊彲鑳戒竴鐩翠笉缁撴潫锛岃秴鏃跺悗寮哄埗閫€鍑猴紝
    // 閬垮厤 systemd 绛夊緟鍒?TimeoutStopSec 鍐?SIGKILL锛堝鑷存仮澶嶈鎷栨參/鏍囪 timeout 澶辫触锛?    if timeout_result.is_err() {
        warn!("graceful drain timed out (long-lived connections), force exiting");
        std::process::exit(0);
    }
    info!("AQUA Server stopped");
}

/// 璇锋眰鏃ュ織鑷姩娓呯悊锛氬垎鎵瑰垹闄よ繃鏈熸暟鎹紝閬垮厤闀夸簨鍔￠攣琛?/// - request_logs锛堢綉鍏虫棩蹇楋級锛?xx 鎴愬姛淇濈暀 30 澶╋紝鍏朵綑鐘舵€侊紙4xx/5xx 绛夛級淇濈暀 90 澶?/// - pf_request_logs锛堝钩鍙版棩蹇楋級锛歴tatus='success' 淇濈暀 30 澶╋紝鍏朵綑淇濈暀 90 澶?async fn cleanup_old_logs(pool: &sqlx::PgPool) {
    // 1. request_logs 闈為敊璇暟鎹紙2xx锛?    batch_delete_logs(pool, "request_logs", "status_code BETWEEN 200 AND 299", "30 days").await;
    // 2. request_logs 閿欒鏁版嵁锛堥潪 2xx锛?    batch_delete_logs(pool, "request_logs", "(status_code < 200 OR status_code > 299)", "90 days").await;
    // 3. pf_request_logs 鎴愬姛鏁版嵁
    batch_delete_logs(pool, "pf_request_logs", "status = 'success'", "30 days").await;
    // 4. pf_request_logs 閿欒鏁版嵁
    batch_delete_logs(pool, "pf_request_logs", "status != 'success'", "90 days").await;
}

/// 鍒嗘壒鍒犻櫎锛堟瘡鎵?5000 琛岋紝闂撮殧 50ms锛岄伩鍏嶉暱閿侊紱杩斿洖鍒犻櫎鎬绘暟锛?async fn batch_delete_logs(pool: &sqlx::PgPool, table: &str, cond: &str, keep: &str) -> u64 {
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

/// SO_REUSEPORT 鐩戝惉锛氱儹鏇存湡闂存柊鏃у疄渚嬪彲鍏变韩鍚屼竴绔彛锛圠inux锛?async fn bind_reuse(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e: std::net::AddrParseError| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    // SO_REUSEPORT锛氬厑璁告柊瀹炰緥涓庢棫瀹炰緥鍦ㄦ粴鍔ㄦ洿鏂版湡闂村叡浜鍙?    set_so_reuse_port(&socket)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

/// 閫氳繃 libc 璁剧疆 SO_REUSEPORT锛坰ocket2 0.5 閮ㄥ垎鐗堟湰涓嶅鍑鸿鏂规硶锛?fn set_so_reuse_port(sock: &socket2::Socket) -> std::io::Result<()> {
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

/// CORS 涓棿浠讹紙澶嶇敤缃戝叧瀵煎嚭鐨勯厤缃級
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

/// HTML 椤甸潰绂佹娴忚鍣ㄧ紦瀛橈紙閬垮厤鏃х増/404 椤甸潰琚暱鏈熺紦瀛樺鑷?椤甸潰涓嶆樉绀?锛?async fn no_cache_html(request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next) -> Response {
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

/// 瀹夊叏鍝嶅簲澶翠腑闂翠欢锛堥槻鐐瑰嚮鍔寔 / MIME 鍡呮帰 / 淇℃伅娉勯湶锛?026-08 瀹夊叏鍔犲浐锛?async fn security_headers(request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Frame-Options", axum::http::HeaderValue::from_static("DENY"));
    headers.insert("X-Content-Type-Options", axum::http::HeaderValue::from_static("nosniff"));
    headers.insert("Referrer-Policy", axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert("Permissions-Policy", axum::http::HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"));
    headers.insert("X-XSS-Protection", axum::http::HeaderValue::from_static("1; mode=block"));
    response
}

/// 骞冲彴 Router锛堥〉闈?+ 闈欐€?+ API锛?fn build_platform_router(state: Arc<AppState>) -> Router {
    use axum::routing::{delete, get, get_service, patch, post, put};
    use tower_http::services::ServeFile;
    use crate::platform::handler as ph;
    let cors = cors_layer(&state.cfg);
    let html = |f: &str| get_service(ServeFile::new(format!("web/platform/static/{f}")));
    Router::new()
        // ===== 鍩虹 =====
        .route("/healthz", get(ph::public::healthz))
        .route("/robots.txt", get(ph::public::robots_txt))
        .route("/sitemap.xml", get(ph::public::sitemap))
        .route("/favicon.ico", get(ph::public::favicon))
        .route("/", get(ph::public::index))
        // ===== 闈欐€侀〉闈?=====
        .route("/login", html("login.html"))
        .route("/register", html("register.html"))
        .route("/reset-password", html("reset-password.html"))
        .route("/models", html("models.html"))
        .route("/docs", html("docs.html"))
        .route("/quick-start", html("quick-start.html"))
        .route("/qq-group", html("qq-group.html"))
        .route("/sponsor", html("sponsor.html"))
        .route("/capabilities", html("capabilities.html"))
        // 鈿狅笍 2026-08-11 QQ 缇よ仈绯婚€氶亾宸插簾寮冿紝椤甸潰涓庤矾鐢变竴骞剁Щ闄?        // .route("/qq-groups", html("qq-groups.html"))
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
        // ===== 妯″瀷鍒楄〃浠ｇ悊 =====
        .route("/v1/models", get(ph::public::api_models))
        .route("/v1/models/", get(ph::public::api_models))
        .route("/api/v1/models", get(ph::public::api_models))
        .route("/api/v1/models/", get(ph::public::api_models))
        // ===== 璁よ瘉 =====
        .route("/api/auth/send-code", post(ph::auth::send_code))
        .route("/api/auth/register", post(ph::auth::register))
        .route("/api/auth/login", post(ph::auth::login))
        .route("/api/auth/logout", post(ph::auth::logout))
        .route("/api/auth/reset-password", post(ph::auth::reset_password))
        .route("/api/auth/verify", get(ph::auth::verify))
        // ===== 瀵硅瘽 =====
        // 缃戦〉瀵硅瘽鍔熻兘宸蹭笅绾匡紙2026-08-08锛夛細浠呬繚鐣欐ā鍨嬪垪琛ㄤ緵妯″瀷骞垮満/鎺у埗鍙颁娇鐢?        .route("/api/chat/models", get(ph::chat::models))
        // ===== 鐢ㄦ埛鎺у埗鍙?=====
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
        // ===== 鍏紑 API =====
        .route("/api/public/stats", get(ph::public::public_stats))
        // 鈿狅笍 2026-08-11 Codex 涓婃父涓嬬嚎锛?api/public/acu-usage 宸叉敞閲婏紙public_acu_usage 鍚屾娉ㄩ噴锛?        // .route("/api/public/acu-usage", get(ph::public::public_acu_usage))
        .route("/api/public/model-capabilities", get(ph::public::public_model_capabilities))
        // ===== 绠＄悊鍚庡彴 =====
        .route("/api/admin/login", post(ph::admin::login))
        .route("/api/admin/logout", post(ph::admin::logout))
        .route("/api/admin/check", get(ph::admin::check))
        .route("/api/admin/login-logs", get(ph::admin::login_logs))
        .route("/api/admin/users", get(ph::admin::users).post(ph::admin::create_user_handler))
        .route("/api/admin/users/{id}", get(ph::admin::user_detail_handler).delete(ph::admin::delete_user_handler))
        .route("/api/admin/users/{id}/ban", put(ph::admin::ban_user_handler).patch(ph::admin::ban_user_handler))
        .route("/api/admin/users/{id}/unban", put(ph::admin::unban_user_handler).patch(ph::admin::unban_user_handler))
        // ===== 铚滅綈 =====
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

/// 缃戝叧 Router锛堝叕寮€ API + 鍋ュ悍妫€鏌?+ 绠＄悊鎺у埗鍙帮級
fn build_gateway_router(state: Arc<AppState>) -> Router {
    use axum::routing::{delete, get, post, put};
    use gateway::handler::{admin, admin_monitoring, public};
    let cors = cors_layer(&state.cfg);
    Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/v1/models", axum::routing::get(public::models_handler))
        .route("/api/v1/models", axum::routing::get(public::models_handler))
        // 鈿狅笍 2026-08-11 Codex 涓婃父涓嬬嚎锛?v1/acu/usage 璺敱宸叉敞閲婏紙acu_usage 鍚屾娉ㄩ噴锛?        // .route("/v1/acu/usage", axum::routing::get(public::acu_usage))
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
        // ===== 缃戝叧绠＄悊鍚庡彴 /gw/admin/* =====
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

/// 缃戝叧鎺у埗鍙伴〉闈紙console.html锛?async fn gw_console() -> Response {
    crate::platform::handler::public::serve_file("web/gateway/static/console.html", "text/html; charset=utf-8").await
}

/// 鍋ュ悍妫€鏌?async fn healthz() -> &'static str {
    "OK"
}

/// 浠?DB 璇诲彇 upstream_master_key锛坆ase64 瑙ｇ爜锛?async fn load_upstream_master_key(pool: &sqlx::PgPool) -> Result<Vec<u8>, String> {
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

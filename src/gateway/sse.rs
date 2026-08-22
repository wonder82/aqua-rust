//! SSE 流式透传：心跳 / 空闲超时 / usage 解析 / partial-success 语义
//! 与 Go 版 internal/pkg/sse/sse.go 对齐

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{interval, Duration, Instant};

use crate::constants::{SSE_CHUNK_IDLE_TIMEOUT_SECS, SSE_KEEPALIVE_INTERVAL_SECS, SSE_MAX_SCAN_BUFFER};

/// SSE 写入器状态（跟踪是否已写入过数据，用于 partial-success 判定）
#[derive(Clone, Default)]
pub struct SseWriter {
    wrote: Arc<AtomicBool>,
}

impl SseWriter {
    pub fn new() -> Self {
        Self { wrote: Arc::new(AtomicBool::new(false)) }
    }
    pub fn committed(&self) -> bool {
        self.wrote.load(Ordering::Relaxed)
    }
    fn mark_written(&self) {
        self.wrote.store(true, Ordering::Relaxed);
    }
}

/// 流式代理：从上游 body 读取 SSE 行并透传，同时解析 usage
/// 返回 (usage_json, chunk_count, 是否正常完成)
pub async fn stream_proxy<R>(reader: R, sink: &mut SseSink) -> (String, u64, bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf_reader = BufReader::with_capacity(64 * 1024, reader);
    let mut line_buf = Vec::with_capacity(4096);

    let mut usage = String::new();
    let mut chunks: u64 = 0;
    let mut completed = false;
    let mut last_data = Instant::now();

    let mut keepalive = interval(Duration::from_secs(SSE_KEEPALIVE_INTERVAL_SECS));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                let idle = last_data.elapsed();
                if idle > Duration::from_secs(SSE_CHUNK_IDLE_TIMEOUT_SECS) {
                    if sink.writer.committed() {
                        sink.write_event(r#"{"error":{"type":"stream_incomplete","code":"stream_idle_timeout","message":"模型响应等待超时，已返回的内容可能不完整"}}"#).await;
                    }
                    return (usage, chunks, false);
                }
                // 心跳保活
                sink.write_comment("ping").await;
            }
            result = read_line(&mut buf_reader, &mut line_buf) => {
                match result {
                    Ok(0) => { // EOF
                        if completed {
                            return (usage, chunks, true);
                        }
                        if sink.writer.committed() {
                            sink.write_event(r#"{"error":{"type":"stream_incomplete","code":"connection_lost","message":"上游连接提前结束，已返回的内容可能不完整"}}"#).await;
                        }
                        return (usage, chunks, false);
                    }
                    Ok(_) => {
                        let line = String::from_utf8_lossy(&line_buf).to_string();
                        line_buf.clear();
                        if line.is_empty() {
                            continue;
                        }
                        last_data = Instant::now();
                        if let Some(data) = line.strip_prefix("data: ") {
                            if data == "[DONE]" {
                                completed = true;
                                sink.write_event("[DONE]").await;
                                return (usage, chunks, true);
                            }
                            sink.write_event(data).await;
                            chunks += 1;
                            if data.contains("\"usage\"") {
                                usage = data.to_string();
                            }
                        }
                        // 其他行（event:/: 心跳等）忽略
                    }
                    Err(_) => {
                        if chunks > 0 {
                            sink.write_event(
                                format!(r#"{{"error":{{"type":"stream_incomplete","code":"connection_lost","message":"上游连接中断，已返回的内容可能不完整","chunks":{}}}}}"#, chunks).as_str()
                            ).await;
                        }
                        return (usage, chunks, false);
                    }
                }
            }
        }
    }
}

async fn read_line<R>(reader: &mut BufReader<R>, buf: &mut Vec<u8>) -> std::io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    reader.read_until(b'\n', buf).await
}

/// SSE 响应通道：将事件发送到 axum 的 Body 流
#[derive(Clone)]
pub struct SseSink {
    pub writer: SseWriter,
    tx: tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
}

impl SseSink {
    pub fn new(tx: tokio::sync::mpsc::Sender<Result<String, std::io::Error>>) -> Self {
        Self { writer: SseWriter::new(), tx }
    }
    pub async fn write_event(&mut self, data: &str) {
        self.writer.mark_written();
        let _ = self.tx.send(Ok(format!("data: {data}\n\n"))).await;
    }
    pub async fn write_comment(&mut self, comment: &str) {
        let _ = self.tx.send(Ok(format!(": {comment}\n\n"))).await;
    }
    pub async fn write_raw(&mut self, raw: &str) {
        self.writer.mark_written();
        let _ = self.tx.send(Ok(raw.to_string())).await;
    }
}

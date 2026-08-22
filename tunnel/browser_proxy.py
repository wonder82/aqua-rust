#!/usr/bin/env python3
"""
DeepSeek 浏览器代理 v4 — 极简稳定版
通过 SOCKS5 隧道 → 家庭宽带 → DeepSeek。
"""
import asyncio, json, sys, time, random
from playwright.async_api import async_playwright

LISTEN = ("127.0.0.1", 5555)
SOCKS5 = "socks5://127.0.0.1:2080"
DEEPSEEK_BASE = "https://chat.deepseek.com"

STEALTH_JS = """
Object.defineProperty(navigator,'webdriver',{get:()=>false});
window.chrome={runtime:{}};
"""

async def handle_client(reader, writer, page, is_healthy, get_last_health):
    try:
        data = await asyncio.wait_for(reader.read(65536), timeout=30)
        if not data:
            return
        request_text = data.decode("utf-8", errors="replace")
        lines = request_text.split("\r\n")
        if not lines:
            return
        parts = lines[0].split(" ")
        if len(parts) < 2:
            return
        method, path = parts[0], parts[1]

        # 健康检查端点
        if path == "/health":
            if is_healthy():
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            else:
                writer.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\n\r\nNOK")
            await writer.drain()
            return

        headers = {}
        body = ""
        body_start = request_text.find("\r\n\r\n")
        if body_start >= 0:
            body = request_text[body_start + 4:]
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

        url = f"{DEEPSEEK_BASE}{path}"
        safe_headers = {}
        for k, v in headers.items():
            if k in ("host", "content-length", "connection", "expect", "transfer-encoding", "cookie"):
                continue
            if not k or not all(c.isalnum() or c in '-_' for c in k):
                continue
            if any(c in v for c in '\n\r'):
                continue
            safe_headers[k] = v
        safe_headers["referer"] = f"{DEEPSEEK_BASE}/"
        safe_headers["origin"] = DEEPSEEK_BASE

        fetch_headers = json.dumps(safe_headers)
        fetch_body = "null" if method == "GET" or not body else json.dumps(body)

        result = await page.evaluate(f"""
            async () => {{
                try {{
                    const resp = await fetch({json.dumps(url)}, {{
                        method: {json.dumps(method)},
                        headers: {fetch_headers},
                        body: {fetch_body},
                        credentials: 'include',
                    }});
                    const text = await resp.text();
                    return {{ status: resp.status, headers: Object.fromEntries(resp.headers.entries()), body: text }};
                }} catch(e) {{
                    return {{ error: String(e) }};
                }}
            }}
        """)

        if "error" in result:
            resp_body = json.dumps({"error": result["error"]})
            status = 502
            ct = "application/json"
        else:
            resp_body = result.get("body", "")
            resp_headers = result.get("headers", {})
            status = result.get("status", 500)
            ct = resp_headers.get('content-type', 'application/json')

        response = f"HTTP/1.1 {status} OK\r\n"
        response += f"Content-Length: {len(resp_body.encode())}\r\n"
        response += f"Content-Type: {ct}\r\n"
        response += "Connection: close\r\n\r\n"
        response += resp_body

        writer.write(response.encode())
        await writer.drain()
    except Exception as e:
        print(f"ERR: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                  "--disable-setuid-sandbox", "--no-first-run", "--no-zygote",
                  "--single-process", "--disable-blink-features=AutomationControlled"],
        )
        context = await browser.new_context(
            proxy={"server": SOCKS5},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
        )
        page = await context.new_page()
        await page.add_init_script(STEALTH_JS)

        # 健康状态
        healthy = False
        last_health = 0

        for attempt in range(10):
            print(f"[Proxy] session attempt {attempt+1}/10...")
            try:
                await page.goto(f"{DEEPSEEK_BASE}/", wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_load_state("networkidle", timeout=30000)
                await asyncio.sleep(2)
            except Exception as e:
                print(f"[Proxy] goto: {e}")
                if attempt >= 3:
                    print(f"[Proxy] retrying after delay...")
                await asyncio.sleep(5)
                continue
            title = await page.title()
            print(f"[Proxy] page: {title}")
            if "ERROR" in title or "Verification" in title:
                await asyncio.sleep(5)
                continue
            healthy = True
            last_health = time.time()
            break
        else:
            print("[Proxy] FATAL: all session attempts failed")
            await browser.close()
            sys.exit(1)

        server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, page, lambda: healthy, lambda: last_health), LISTEN[0], LISTEN[1]
        )
        print(f"[Proxy] listening {LISTEN[0]}:{LISTEN[1]}")

        async def refresh():
            nonlocal healthy, last_health
            while True:
                await asyncio.sleep(600)
                print("[Proxy] refresh...")
                try:
                    await page.goto(f"{DEEPSEEK_BASE}/", wait_until="domcontentloaded", timeout=30000)
                    await asyncio.sleep(2)
                    healthy = True
                    last_health = time.time()
                except Exception as e:
                    print(f"[Proxy] refresh: {e}")
                    healthy = False

        asyncio.create_task(refresh())
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
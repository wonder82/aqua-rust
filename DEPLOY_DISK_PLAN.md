# Ubuntu 部署磁盘空间规划

## 项目概述
- **项目名称**: Aqua-Rust (多协议 AI API 网关 + 用户平台)
- **源码大小**: ~1.5 MB
- **编译产物**: ~15-20 MB (release build with LTO)

---

## 磁盘空间需求估算

### 1. 系统基础 (Ubuntu 24.04 LTS)
| 组件 | 空间需求 | 说明 |
|------|----------|------|
| Ubuntu 系统 | 2-3 GB | 最小安装 + 常用工具 |
| 安全更新 | 500 MB | 预留空间 |
| **小计** | **2.5-3.5 GB** | |

### 2. 开发工具链 (仅编译时需要)
| 组件 | 空间需求 | 说明 |
|------|----------|------|
| Rust 工具链 | 2-3 GB | rustc, cargo, rustup |
| 编译缓存 (target/) | 500 MB-1 GB | 首次编译,后续增量编译较小 |
| **小计** | **2.5-4 GB** | 编译完成后可删除 |

### 3. 运行时服务
| 组件 | 空间需求 | 说明 |
|------|----------|------|
| PostgreSQL 16 | 500 MB | 数据库程序 + 默认配置 |
| Redis | 50-100 MB | 缓存服务 |
| Cloudflared | 50 MB | 隧道客户端 |
| Nginx (可选) | 50 MB | 反向代理,可省略 |
| **小计** | **650 MB-700 MB** | |

### 4. 应用程序
| 组件 | 空间需求 | 说明 |
|------|----------|------|
| aqua-server 二进制 | 15-20 MB | Release build |
| 配置文件 (.env) | 1 KB | 环境变量 |
| 静态文件 (web/) | 5-10 MB | HTML/CSS/JS |
| **小计** | **20-30 MB** | |

### 5. 运行时数据
| 组件 | 空间需求 | 说明 |
|------|----------|------|
| PostgreSQL 数据库 | 100-500 MB | 取决于用户量和会话数 |
| 日志文件 | 50-200 MB/月 | 可配置日志轮转 |
| 临时文件 | 50 MB | 缓存、临时存储 |
| **小计** | **200 MB-750 MB** | |

---

## 总空间需求汇总

| 类别 | 最小需求 | 推荐配置 | 说明 |
|------|----------|----------|------|
| 系统基础 | 3 GB | 4 GB | Ubuntu + 工具 |
| 运行时服务 | 700 MB | 1 GB | PostgreSQL + Redis + Cloudflared |
| 应用程序 | 30 MB | 50 MB | 二进制 + 配置 + 静态文件 |
| 运行时数据 | 200 MB | 1 GB | 数据库 + 日志 |
| **总计** | **~4 GB** | **~6 GB** | |

---

## 推荐磁盘分区方案

### 方案 A: 最小部署 (4 GB VPS)
```
/           3.5 GB    系统 + 应用
swap        512 MB    交换空间 (可选)
```
**适用场景**: 腾讯云/阿里云 2核2G 免费套餐

### 方案 B: 标准部署 (8 GB VPS)
```
/           4 GB      系统 + 应用
/var        2 GB      PostgreSQL 数据 + 日志
swap        1 GB      交换空间 (编译时需要)
/tmp        1 GB      临时文件
```
**适用场景**: 需要编译 Rust 代码的服务器

### 方案 C: 开发部署 (16 GB VPS)
```
/           4 GB      系统 + 应用
/var        4 GB      PostgreSQL 数据 + 日志
/home       4 GB      开发文件 + 编译缓存
swap        2 GB      交换空间
/tmp        2 GB      临时文件
```
**适用场景**: 需要在服务器上编译和调试的环境

---

## 空间优化建议

### 1. 编译完成后清理
```bash
# 删除编译缓存 (节省 500MB-1GB)
rm -rf /aqua-rust/target/

# 或仅保留二进制
rm -rf /aqua-rust/target/debug/
```

### 2. 日志轮转配置
```bash
# /etc/logrotate.d/aqua-rust
/var/log/aqua-rust/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
}
```

### 3. PostgreSQL 优化
```sql
-- 减少 WAL 日志保留
ALTER SYSTEM SET wal_keep_size = '64MB';
ALTER SYSTEM SET max_wal_size = '256MB';
SELECT pg_reload_conf();
```

### 4. 交换空间 (Swap)
```bash
# 如果内存 < 4GB,建议创建 1-2GB swap
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

---

## 磁盘使用监控

### 检查磁盘使用
```bash
# 查看整体使用情况
df -h

# 查看目录大小
du -sh /aqua-rust/
du -sh /var/lib/postgresql/
du -sh /var/log/

# 查找大文件
sudo find / -type f -size +100M -exec ls -lh {} \;
```

### 设置磁盘告警
```bash
# 简单的磁盘使用检查脚本
#!/bin/bash
USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $USAGE -gt 80 ]; then
    echo "磁盘使用率过高: ${USAGE}%" | mail -s "磁盘告警" admin@example.com
fi
```

---

## 最低配置要求

| 配置项 | 最低要求 | 推荐配置 |
|--------|----------|----------|
| CPU | 1 核 | 2 核 |
| 内存 | 1 GB | 2 GB |
| 磁盘 | 4 GB | 8 GB |
| 交换 | 512 MB | 1 GB |
| 网络 | 1 Mbps | 3 Mbps |

---

## 注意事项

1. **编译 Rust 需要内存**: 首次编译建议有 2GB 内存 + 1GB swap,否则可能 OOM
2. **PostgreSQL 数据增长**: 每个用户会话约 1-5KB,1000 用户约 1-5MB
3. **日志是主要空间消耗**: 配置日志轮转非常重要
4. **定期清理**: 建议每周检查一次磁盘使用情况

---

## 快速部署命令

```bash
# 1. 检查磁盘空间
df -h

# 2. 如果空间不足,清理系统
sudo apt clean
sudo apt autoremove
sudo journalctl --vacuum-time=7d

# 3. 创建 swap (如果需要)
sudo fallocate -l 1G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# 4. 继续部署...
```

-- =====================================================================
-- 005: 修复外键约束问题（H9, M22）
--
-- H9 (高危): pf_request_logs.user_id 外键缺 ON DELETE CASCADE
--   删除用户时会产生孤儿平台请求日志记录。
--
-- M22 (中危): client_api_keys.client_id 外键缺 ON DELETE CASCADE
--   删除客户端时会产生孤儿 API 密钥记录。
--
-- 说明：PostgreSQL 不支持 ADD CONSTRAINT IF NOT EXISTS，
--       因此采用 DROP CONSTRAINT IF EXISTS + ADD CONSTRAINT 的幂等模式。
-- 日期：2026-07-30
-- =====================================================================

BEGIN;

-- ========== H9: 修复 pf_request_logs.user_id 外键 ==========
-- 原: REFERENCES users(id)              （无 ON DELETE 行为，默认 NO ACTION）
-- 新: REFERENCES users(id) ON DELETE CASCADE
ALTER TABLE pf_request_logs DROP CONSTRAINT IF EXISTS pf_request_logs_user_id_fkey;
ALTER TABLE pf_request_logs ADD CONSTRAINT pf_request_logs_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- ========== M22: 修复 client_api_keys.client_id 外键 ==========
-- 原: REFERENCES clients(id)            （无 ON DELETE 行为，默认 NO ACTION）
-- 新: REFERENCES clients(id) ON DELETE CASCADE
ALTER TABLE client_api_keys DROP CONSTRAINT IF EXISTS client_api_keys_client_id_fkey;
ALTER TABLE client_api_keys ADD CONSTRAINT client_api_keys_client_id_fkey
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE;

COMMIT;

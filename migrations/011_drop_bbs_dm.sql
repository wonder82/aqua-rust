-- 011_drop_bbs_dm.sql  下线 BBS 论坛与用户私信（DM）功能
-- 删除 009_bbs.sql / 010_dm.sql 建的表与字段；已在老库执行过 009/010 的场景可直接跑本迁移

DROP TABLE IF EXISTS bbs_reports;
DROP TABLE IF EXISTS bbs_sensitive_words;
DROP TABLE IF EXISTS bbs_notifications;
DROP TABLE IF EXISTS bbs_favorites;
DROP TABLE IF EXISTS bbs_likes;
DROP TABLE IF EXISTS bbs_replies;
DROP TABLE IF EXISTS bbs_posts;
DROP TABLE IF EXISTS bbs_categories;
DROP TABLE IF EXISTS bbs_attachments;
DROP TABLE IF EXISTS bbs_bans;

DROP TABLE IF EXISTS dm_messages;
DROP TABLE IF EXISTS dm_conversations;

ALTER TABLE users DROP COLUMN IF EXISTS bbs_role;

-- =====================================================================
-- latihan/analisis_log.sql  --  Analisis Log API (Tugas Pertemuan 7)
--
-- Cara pakai:
--   mysql -u root kampus_db < latihan/analisis_log.sql
--   atau jalankan tiap query satu per satu di MySQL monitor / phpMyAdmin.
-- =====================================================================

USE kampus_db;

-- ---------------------------------------------------------------------
-- QUERY 1: Jumlah login GAGAL per username
--   Berguna untuk mendeteksi akun mana yang sering jadi target serangan
--   brute force. Status 401 pada path /login = percobaan login gagal.
-- ---------------------------------------------------------------------
SELECT
    username,
    COUNT(*)                          AS jumlah_gagal,
    MAX(waktu)                        AS percobaan_terakhir
FROM log_api
WHERE status = 401
  AND path LIKE '%/login'
  AND username IS NOT NULL
GROUP BY username
ORDER BY jumlah_gagal DESC;


-- ---------------------------------------------------------------------
-- QUERY 2: 5 IP dengan request TERBANYAK
--   Berguna untuk mendeteksi IP yang melakukan DDoS atau scraping.
--   IP dengan request sangat banyak perlu diwaspadai / diblokir firewall.
-- ---------------------------------------------------------------------
SELECT
    ip,
    COUNT(*)                          AS total_request,
    SUM(status = 200)                 AS request_sukses,
    SUM(status IN (401,403,429))      AS request_ditolak,
    MIN(waktu)                        AS pertama_kali,
    MAX(waktu)                        AS terakhir_kali
FROM log_api
GROUP BY ip
ORDER BY total_request DESC
LIMIT 5;


-- ---------------------------------------------------------------------
-- QUERY 3: Jumlah status 401 / 403 / 429 per HARI
--   401 = belum login / token tidak valid (autentikasi gagal)
--   403 = sudah login tapi tidak punya izin (otorisasi gagal)
--   429 = terlalu banyak request (rate limit kena)
--   Berguna untuk melihat tren ancaman dari waktu ke waktu.
-- ---------------------------------------------------------------------
SELECT
    DATE(waktu)                       AS hari,
    SUM(status = 401)                 AS gagal_autentikasi_401,
    SUM(status = 403)                 AS ditolak_otorisasi_403,
    SUM(status = 429)                 AS rate_limit_429,
    COUNT(*)                          AS total_request
FROM log_api
GROUP BY DATE(waktu)
ORDER BY hari DESC;

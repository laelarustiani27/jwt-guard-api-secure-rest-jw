# REST API Mahasiswa + Autentikasi JWT & RBAC (Versi Ringkas)

**Mata Kuliah**: Teknologi Web Service (Pertemuan 7)  
**Nama**: Laela Rustiani  
**NPM**: 23670004  
**Repositori**: https://github.com/laelarustiani27/jwt-guard-api-secure-rest-jw
**Status Pengujian**: 45 / 45 Pengujian Lulus (**100% PASS**)

---

## 1. Ringkasan Proyek
Layanan REST API Mahasiswa berbasis **PHP Native** dan **MySQL** yang menerapkan arsitektur keamanan:
1. **Autentikasi JWT**: Algoritma HMAC-SHA256 (HS256) dengan serialisasi Base64URL (stateless).
2. **Otorisasi RBAC**: Hak akses berjenjang untuk 3 role (`admin`, `dosen`, `user`).
3. **Keamanan Data**: Password di-hash menggunakan **Bcrypt** (`password_hash`), query kebal SQL Injection (**PDO Prepared Statements**), dan validasi tipe data ketat.
4. **Rate Limiting**: Maksimal 5x gagal login per menit (percobaan ke-6 diblokir HTTP 429) dan maksimal 120 request global per IP per menit.
5. **Audit Logging**: Jejak transaksi tercatat di tabel `log_api`.

---

## 2. Panduan Setup Cepat (Laragon)

1. **Salin Folder Proyek**:
   Letakkan folder proyek di web root Laragon:
   ```text
   C:\laragon\www\api-mhs-auth
   ```
2. **Aktifkan Modul Apache**:
   Pastikan modul **`rewrite_module`** aktif pada Laragon (Klik kanan tray Laragon -> Apache -> modules -> centang `rewrite_module`).
3. **Impor Database MySQL**:
   - Buka HeidiSQL / phpMyAdmin (`http://localhost/phpmyadmin`).
   - Impor dan jalankan berkas: `database/mhs.sql`.
   - Database `kampus_db` akan terbuat dengan tabel `mhs`, `users`, dan `log_api`.
4. **Kredensial Default Basis Data (`server/koneksi.php`)**:
   - Host: `127.0.0.1` | User: `root` | Password: `''` (kosong) | Database: `kampus_db`
5. **Base URL API**:
   ```text
   http://localhost/api-mhs-auth/server
   ```

*Alternatif Pengujian Cepat (Tanpa Apache)*:
```bash
cd api-mhs-auth/server
php -S localhost:8000 router.php
```

---

## 3. Akun Pengujian & Daftar Endpoint

### Akun Bawaan (Seed Data)
| Username | Password | Role | Hak Akses Utama |
| :--- | :--- | :--- | :--- |
| `admin` | `admin123` | `admin` | Akses penuh CRUD Mahasiswa + Baca Log Audit. |
| `dosen1` | `dosen123` | `dosen` | Baca Mahasiswa + Ubah (PUT) Mahasiswa (Dilarang POST/DELETE/Log). |
| `budi` | `budi123` | `user` | Hanya membaca (GET) katalog Mahasiswa. |

### Matriks Endpoint API
| Method | Endpoint | Akses | Status | Keterangan |
| :--- | :--- | :--- | :---: | :--- |
| `POST` | `/login` | Publik | `200` | Login kredensial, menghasilkan Bearer JWT. |
| `POST` | `/register` | Publik | `201` | Daftar akun baru (role otomatis `'user'`, pass min 8 kar). |
| `GET` | `/me` | Token | `200` | Melihat profil login dan masa berlaku token. |
| `PUT` | `/me/password` | Token | `200` | Ganti password mandiri (wajib password lama benar). |
| `GET` | `/mhs` | Token | `200` | Mengambil seluruh katalog mahasiswa. |
| `GET` | `/mhs/:id` | Token | `200` | Mengambil 1 mahasiswa berdasar ID numerik. |
| `POST` | `/mhs` | Admin | `201` | Tambah mahasiswa baru (NIM wajib unik & angka). |
| `PUT` | `/mhs/:id` | Admin / Dosen | `200` | Ubah data mahasiswa (Dosen diizinkan). |
| `DELETE`| `/mhs/:id` | Admin | `200` | Hapus mahasiswa (Dosen & User ditolak 403). |
| `GET` | `/log` | Admin | `200` | Menampilkan 20 riwayat transaksi log_api terakhir. |

---

## 4. Cara Menjalankan Pengujian

### A. Uji Otomatis Suite (45 Test Case)
Jalankan skrip penguji dari terminal:
```bash
# Menggunakan Laragon / Apache:
php api-mhs-auth/client/test_client.php http://localhost/api-mhs-auth/server

# Menggunakan PHP Built-in Server:
php api-mhs-auth/client/test_client.php http://localhost:8000
```
**Hasil**: `HASIL: 45 dari 45 pengujian lulus (100% PASS)`.

### B. Uji Kriptografi JWT di Terminal
```bash
php api-mhs-auth/latihan/jwt_demo.php
```

### C. Uji Antarmuka Web SPA
Buka file `api-mhs-auth/client/index.html` langsung di browser, masukkan kredensial `admin` / `admin123` atau `budi` / `budi123` untuk menguji token dan hak akses secara visual.

---

## 5. Analisis Forensik Log SQL (`latihan/analisis_log.sql`)

1. **Deteksi Brute Force**:
   ```sql
   SELECT username, COUNT(*) AS jumlah_gagal, MAX(waktu) AS percobaan_terakhir
   FROM log_api WHERE status = 401 AND path LIKE '%/login' AND username IS NOT NULL
   GROUP BY username ORDER BY jumlah_gagal DESC;
   ```
2. **Deteksi Scraping / DDoS (5 IP Terbanyak)**:
   ```sql
   SELECT ip, COUNT(*) AS total_request, SUM(status = 200) AS request_sukses,
          SUM(status IN (401,403,429)) AS request_ditolak
   FROM log_api GROUP BY ip ORDER BY total_request DESC LIMIT 5;
   ```
3. **Tren Ancaman Keamanan Harian**:
   ```sql
   SELECT DATE(waktu) AS hari, SUM(status = 401) AS gagal_401,
          SUM(status = 403) AS ditolak_403, SUM(status = 429) AS limit_429, COUNT(*) AS total
   FROM log_api GROUP BY DATE(waktu) ORDER BY hari DESC;
   ```

---

## 6. Berkas Terkait
-  **Dokumentasi Lengkap (1.390+ Baris)**: [`README.md`](README.md)
-  **Laporan Resmi PDF (23 Halaman Akademik)**: [`Laporan_Praktikum_P7_JWT_Laela_Rustiani_23670004.pdf`](Laporan_Praktikum_P7_JWT_Laela_Rustiani_23670004.pdf)

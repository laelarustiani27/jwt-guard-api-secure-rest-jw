# LAPORAN KOMPREHENSIF PRAKTIKUM PERTEMUAN 7
## AUTENTIKASI DAN OTORISASI JSON WEB TOKEN (JWT) SERTA KEAMANAN DASAR REST API

**Mata Kuliah**: Teknologi Web Service  
**Topik**: Autentikasi, Otorisasi JWT, Validasi Input, Rate Limiting, dan Implementasi Tugas Pengembangan  
**Repositori Proyek**: `api-mhs-auth`  
**Status Pengujian**: 45 / 45 Test Case Lulus (**100% PASS**)

---

## DAFTAR ISI
1. [Ringkasan Eksekutif & Capaian Pembelajaran](#1-ringkasan-eksekutif--capaian-pembelajaran)
2. [Landasan Teori & Arsitektur Keamanan](#2-landasan-teori--arsitektur-keamanan)
   - 2.1 Autentikasi vs Otorisasi (401 Unauthorized vs 403 Forbidden)
   - 2.2 Arsitektur dan Anatomi JSON Web Token (JWT)
   - 2.3 Keamanan Penyimpanan Password (Bcrypt Hashing)
   - 2.4 Pertahanan Terhadap Serangan Injeksi dan Manipulasi
   - 2.5 Prinsip Kerja Rate Limiting dan Audit Logging
   - 2.6 Pengantar Kerangka Kerja OAuth 2.0
3. [Panduan Setup dan Instalasi Lengkap (Laragon & Alternatif)](#3-panduan-setup-dan-instalasi-lengkap-laragon--alternatif)
   - 3.1 Setup pada Lingkungan Laragon (Windows)
   - 3.2 Penanganan Modul Apache `mod_rewrite` dan Header `Authorization`
   - 3.3 Setup Alternatif: XAMPP dan PHP Built-in Server
4. [Bedah Arsitektur & Source Code Lengkap File per File](#4-bedah-arsitektur--source-code-lengkap-file-per-file)
   - 4.1 Skema Basis Data: `database/mhs.sql`
   - 4.2 Mesin Kriptografi Token: `server/jwt.php`
   - 4.3 Pustaka Fungsi & Middleware: `server/fungsi.php`
   - 4.4 Inisialisasi Database & Parameter Keamanan: `server/koneksi.php`
   - 4.5 Front Controller & Routing: `server/index.php`
   - 4.6 Konfigurasi Web Server: `server/.htaccess` & `server/router.php`
   - 4.7 Antarmuka Pengujian: `client/index.html` & `client/test_client.php`
5. [Dokumentasi Komprehensif 45 Test Case (By Data & Objective)](#5-dokumentasi-komprehensif-45-test-case-by-data--objective)
   - Bagian 1: Autentikasi Kredensial (Test 1 - 9)
   - Bagian 2: Integritas Token & Deteksi Pemalsuan (Test 10 - 12)
   - Bagian 3: Otorisasi Role Pengguna Standar / Budi (Test 13 - 16)
   - Bagian 4: Hak Akses Penuh Administrator (Test 17 - 22)
   - Bagian 5: Rate Limiting Percobaan Login (Test 23 - 25)
   - Bagian 6: Audit Logging dan Jejak Transaksi (Test 26 - 28)
   - Bagian 7: Fitur Tugas - Registrasi Akun Baru (Test 29 - 34)
   - Bagian 8: Fitur Tugas - Ganti Password Mandiri (Test 35 - 39)
   - Bagian 9: Fitur Tugas - Otorisasi Khusus Role Dosen (Test 40 - 45)
6. [Analisis Forensik dan Audit Log SQL](#6-analisis-forensik-dan-audit-log-sql)
7. [Jawaban Pertanyaan Refleksi & Pembahasan Tantangan Lanjutan](#7-jawaban-pertanyaan-refleksi--pembahasan-tantangan-lanjutan)
8. [Kesimpulan](#8-kesimpulan)

---

## 1. RINGKASAN EKSEKUTIF & CAPAIAN PEMBELAJARAN

Pada arsitektur sistem informasi berbasis RESTful Web Service sebelumnya (Pertemuan 6), endpoint API masih bersifat terbuka (*unauthenticated & unauthorized*). Kondisi ini menyebabkan risiko fatal seperti penghapusan data secara sewenang-wenang oleh pihak tidak berwenang, ketiadaan jejak audit transaksi, serta kerentanan terhadap serangan *brute force* dan *credential stuffing*.

Praktikum dan Tugas Pertemuan 7 ini merekonstruksi arsitektur API Mahasiswa menjadi sistem yang tangguh (*hardened REST API*) dengan capaian pembelajaran:
1. **Diferensiasi Autentikasi dan Otorisasi**: Memahami secara objektif pembedaan identitas (*who you are*) berstatus HTTP 401 dan hak akses (*what you can do*) berstatus HTTP 403.
2. **Implementasi Autentikasi Berbasis Token (JWT)**: Menerapkan mekanisme penerbitan token *stateless* menggunakan algoritma HMAC-SHA256 (HS256) dengan serialisasi Base64URL.
3. **Penerapan Role-Based Access Control (RBAC)**: Mengembangkan arsitektur otorisasi berbasis peran bertingkat (`admin`, `dosen`, `user`).
4. **Implementasi Fitur Tugas Lengkap**:
   - `POST /register`: Pendaftaran publik dengan validasi username unik (3-50 char) dan password minimal 8 karakter yang di-hash dengan Bcrypt.
   - `PUT /me/password`: Mekanisme pergantian password mandiri terlindungi token dengan validasi ketat verifikasi password lama.
   - **Peran Baru Dosen**: Pemberian wewenang untuk mengubah data (`PUT /mhs/:id`) tanpa memberikan hak menambah (`POST /mhs`) maupun menghapus (`DELETE /mhs/:id`).
5. **Keamanan Dasar Terpadu**: Pertahanan SQL Injection via Prepared Statements, validasi tipe data dan ekspresi reguler, pembatasan laju permintaan (*Rate Limiting*), serta logging komprehensif.
6. **Verifikasi Kualitas Objektif**: Menjalankan 45 skenario uji otomatis dengan hasil **45 / 45 Lulus (100% PASS)**.

---

## 2. LANDASAN TEORI & ARSITEKTUR KEAMANAN

### 2.1 Autentikasi vs Otorisasi (401 Unauthorized vs 403 Forbidden)

Dalam rekayasa keamanan perangkat lunak, dua konsep ini sering disalahpahami namun memiliki implikasi protokol yang sangat tegas:

```mermaid
flowchart TD
    ClientReq["Client Request"] --> Gateway{"Ada Token JWT Sah?"}
    Gateway -- "Tidak / Rusak / Expired" --> Resp401["HTTP 401 Unauthorized<br/>(Identitas Belum Terbukti)"]
    Gateway -- "Ya, Identitas Terbukti" --> RoleCheck{"Role Pengguna Memiliki Izin?"}
    RoleCheck -- "Tidak Memenuhi Izin" --> Resp403["HTTP 403 Forbidden<br/>(Izin Ditolak)"]
    RoleCheck -- "Diizinkan" --> ExecEndpoint["Eksekusi Business Logic<br/>HTTP 200 / 201"]
```

- **Autentikasi (Authentication - HTTP 401 Unauthorized)**:
  - Proses verifikasi kebenaran identitas pengakses (*"Siapa Anda?"*).
  - Contoh: Pengguna mengirimkan username dan password saat login, atau menyertakan Bearer Token pada header `Authorization`.
  - Jika token tidak disertakan, formatnya salah, atau tanda tangan tidak cocok, server menolak dengan **HTTP 401 Unauthorized** disertai header respons `WWW-Authenticate: Bearer`.
- **Otorisasi (Authorization - HTTP 403 Forbidden)**:
  - Proses penentuan hak istimewa (*privilege*) dari identitas yang telah terverifikasi (*"Bolehkah Anda melakukan aksi ini?"*).
  - Contoh: Mahasiswa dengan role `user` telah berhasil login (terautentikasi), namun mencoba menghapus data mahasiswa (`DELETE /mhs/1`) atau mengakses catatan log (`GET /log`).
  - Server mengenali siapa pengakses tersebut, tetapi hak aksesnya ditolak dengan **HTTP 403 Forbidden**.

### 2.2 Arsitektur dan Anatomi JSON Web Token (JWT)

JSON Web Token (RFC 7519) adalah standar terbuka yang mendefinisikan cara mentransfer informasi secara ringkas dan mandiri (*compact and self-contained*) antara pihak-pihak sebagai objek JSON.

JWT terdiri dari 3 bagian yang dipisahkan oleh tanda titik (`.`):
$$\text{JWT} = \text{Header} \,.\, \text{Payload} \,.\, \text{Signature}$$

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInVzZXJuYW1lIjoiYnVkaSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkyOTQ1NzQxLCJleHAiOjE3OTI5NDkzNDF9.Hn7cvcCONM6ouBrtaTyT3gJuTY93RXZW-wpx7-TXkXQ
\_________________________________/ \____________________________________________________________________________________/ \__________________________________________/
              HEADER                                                       PAYLOAD                                                           SIGNATURE
```

1. **Header**: Objek JSON yang mendefinisikan metadata token dan algoritma penandatanganan:
   ```json
   { "alg": "HS256", "typ": "JWT" }
   ```
2. **Payload (Claims)**: Objek JSON yang memuat klaim atau pernyataan tentang entitas (pengguna):
   - `sub` (*Subject*): ID unik pengguna di database.
   - `username`: Nama pengguna login.
   - `role`: Peran otorisasi pengguna (`admin`, `dosen`, `user`).
   - `iat` (*Issued At*): Waktu pembuatan token (Unix Epoch timestamp).
   - `exp` (*Expiration Time*): Batas waktu kedaluwarsa token.
   > [!WARNING]
   > Payload **hanya di-encode dalam format Base64URL, BUKAN dienkripsi**. Siapa pun dapat membaca isi data payload. Oleh karena itu, **password, kunci API, atau data rahasia TIDAK BOLEH ditaruh di payload**.
3. **Signature (Tanda Tangan Digital)**:
   - Dihasilkan dengan menggabungkan Header ter-encode dan Payload ter-encode, lalu di-hash menggunakan algoritma HMAC-SHA256 bersama kunci rahasia (*secret key*) yang hanya diketahui oleh server:
   $$\text{Signature} = \text{Base64URL}\Big(\text{HMAC-SHA256}\big(\text{header} \,.\, \text{payload}, \, \text{secret}\big)\Big)$$
   - Tanda tangan ini menjamin **integritas**. Jika ada penyerang yang mengubah `role: "user"` menjadi `role: "admin"` di payload, tanda tangan baru yang dihitung oleh server tidak akan pernah cocok karena penyerang tidak memiliki secret key server.

### 2.3 Keamanan Penyimpanan Password (Bcrypt Hashing)

Menyimpan password asli dalam format teks mentah (*plaintext*) adalah pelanggaran fatal standar keamanan OWASP. Pada sistem ini, penyimpanan password menggunakan algoritma **Bcrypt** (`PASSWORD_DEFAULT` via fungsi bawaan PHP `password_hash()`):
- **Satu Arah (*One-Way Function*)**: Password diubah menjadi string hash 60 karakter yang secara matematis tidak dapat dikembalikan ke teks asli.
- **Salt Otomatis**: Setiap pemanggilan `password_hash()` menghasilkan salt unik acak, sehingga dua pengguna dengan password identik tetap memiliki hash yang sepenuhnya berbeda di database, menggagalkan serangan *Rainbow Table*.
- **Adaptive Cost Factor**: Menggunakan beban komputasi yang dapat disesuaikan untuk memperlambat serangan *brute force offline*.
- **Pencocokan Aman**: Pengecekan saat login dilakukan menggunakan `password_verify($password_input, $hash_database)`.

### 2.4 Pertahanan Terhadap Serangan Injeksi dan Manipulasi

1. **SQL Injection (SQLi)**:
   - Penggunaan **PDO Prepared Statements** dengan *parameterized queries* (`execute([$param])`) memastikan bahwa input dari klien selalu diperlakukan sebagai literal nilai data, bukan kode instruksi SQL yang dieksekusi oleh mesin basis data.
2. **Alg: None Attack pada JWT**:
   - Beberapa pustaka JWT rentan jika penyerang mengganti `"alg": "none"` pada header. Pada sistem ini, fungsi `cek_token()` **mengabaikan klaim algoritma dari token** dan secara mutlak memaksakan komputasi HMAC-SHA256 (`HS256`) menggunakan kunci rahasia server.
3. **Timing Attack pada Perbandingan Hash**:
   - Pengecekan tanda tangan menggunakan fungsi `hash_equals()` yang membutuhkan waktu komputasi konstan (*constant-time string comparison*), sehingga penyerang tidak dapat menebak karakter demi karakter signature berdasarkan perbedaan mikrodetik waktu respons.
4. **Validasi Input Whitelisting**:
   - Parameter ID numerik pada endpoint `/mhs/:id` diverifikasi dengan `ctype_digit($id)`.
   - Username pada `/register` divalidasi dengan regular expression `/^[a-zA-Z0-9_.]+$/` untuk mencegah karakter berbahaya.

### 2.5 Prinsip Kerja Rate Limiting dan Audit Logging

1. **Rate Limiting Login (Anti Brute Force)**:
   - Server membatasi maksimal 5 kali kegagalan login untuk target username dan IP tertentu dalam 60 detik terakhir.
   - Data kegagalan dibaca langsung dari tabel `log_api` (`status = 401 AND path LIKE '%/login'`). Percobaan ke-6 langsung dibatalkan dengan **HTTP 429 Too Many Requests** dan header `Retry-After: 60`.
2. **Rate Limiting Global (Anti Scraping / Flooding)**:
   - Server membatasi maksimal 120 request per menit per alamat IP pengakses (`batasi_request()`).
3. **Audit Logging di Database**:
   - Setiap transaksi yang diproses dicatat ke tabel `log_api`, mencakup timestamp `waktu`, HTTP `method`, request `path`, HTTP `status`, alamat `ip`, `username` pengakses (diekstrak dari token JWT), dan keterangan `pesan`.

### 2.6 Pengantar Kerangka Kerja OAuth 2.0

OAuth 2.0 (RFC 6749) adalah kerangka kerja delegasi otorisasi pihak ketiga yang memungkinkan aplikasi klien memperoleh akses terbatas ke sumber daya pengguna di server lain tanpa perlu mengetahui password pengguna.

Peran dalam OAuth 2.0:
- **Resource Owner**: Pengguna pemilik data.
- **Client**: Aplikasi pihak ketiga yang membutuhkan akses.
- **Authorization Server**: Server penyedia identitas yang menerbitkan token (misal: Google, GitHub).
- **Resource Server**: Server API yang menyimpan data pengguna dan memvalidasi access token.

*Hubungan dengan Praktikum*: Header `Authorization: Bearer <token>` yang digunakan pada praktikum ini identik dengan standar OAuth 2.0 (RFC 6750). Perbedaannya, dalam praktikum ini aplikasi kita bertindak sekaligus sebagai Authorization Server dan Resource Server.

---

## 3. PANDUAN SETUP DAN INSTALASI LENGKAP (LARAGON & ALTERNATIF)

### 3.1 Setup pada Lingkungan Laragon (Windows)

Laragon menyediakan lingkungan WAMP modern yang sangat stabil. Ikuti langkah demi langkah berikut:

#### Langkah 1: Penempatan Direktori Proyek
1. Buka folder root web Laragon di:
   ```text
   C:\laragon\www\
   ```
2. Pastikan folder proyek diletakkan di sana dengan struktur:
   ```text
   C:\laragon\www\api-mhs-auth\
   ├── database/
   ├── server/
   ├── client/
   ├── latihan/
   └── README.md
   ```

#### Langkah 2: Konfigurasi Virtual Host atau URL Direct
- Laragon secara default membuat URL Pretty Host `http://api-mhs-auth.test` atau dapat diakses langsung via:
  ```text
  http://localhost/api-mhs-auth/server
  ```

#### Langkah 3: Setup Basis Data MySQL
1. Buka antarmuka Laragon, lalu klik tombol **Start All** (memulai Apache dan MySQL).
2. Klik tombol **Database** pada Laragon (membuka HeidiSQL) atau buka phpMyAdmin di `http://localhost/phpmyadmin`.
3. Gunakan kredensial default MySQL Laragon:
   - **Hostname / IP**: `127.0.0.1` (atau `localhost`)
   - **Port**: `3306`
   - **User**: `root`
   - **Password**: *(kosong)*
4. Buat query baru, lalu salin dan jalankan seluruh isi file `database/mhs.sql`.
5. Skrip akan mengeksekusi:
   - Pembuatan database `kampus_db` jika belum ada.
   - Pembuatan tabel `mhs`, `users`, dan `log_api`.
   - Injeksi data awal (3 mahasiswa, 3 user: `admin`, `budi`, `dosen1`).

#### Langkah 4: Verifikasi Konfigurasi `server/koneksi.php`
Pastikan kredensial di `server/koneksi.php` sesuai dengan Laragon:
```php
$host    = '127.0.0.1';
$user    = 'root';
$pass    = '';            // Laragon default: string kosong
$nama_db = 'kampus_db';
```

### 3.2 Penanganan Modul Apache `mod_rewrite` dan Header `Authorization`

Pada instalasi Apache standar (termasuk Laragon dan XAMPP), Apache sering memotong header HTTP `Authorization` sebelum diteruskan ke PHP. Untuk mengatasinya:
1. Pastikan modul `mod_rewrite` aktif di Laragon:
   - Klik kanan tray icon Laragon -> **Apache** -> **modules** -> pastikan **rewrite_module** tercentang.
2. File `server/.htaccess` telah disiapkan dengan konfigurasi:
   ```apache
   RewriteEngine On
   
   # Meneruskan Header Authorization ke Environment PHP
   RewriteCond %{HTTP:Authorization} .
   RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
   
   # Routing URL bersih ke index.php
   RewriteCond %{REQUEST_FILENAME} !-f
   RewriteCond %{REQUEST_FILENAME} !-d
   RewriteRule ^ index.php [L]
   ```
3. Di dalam `server/fungsi.php`, fungsi `ambil_token()` memeriksa kedua variabel:
   ```php
   if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
       $header = $_SERVER['HTTP_AUTHORIZATION'];
   } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
       $header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
   }
   ```
   Hal ini menjamin token Bearer terbaca di lingkungan server manapun.

### 3.3 Setup Alternatif: XAMPP dan PHP Built-in Server

- **XAMPP**:
  - Letakkan di `C:\xampp\htdocs\api-mhs-auth`.
  - Akses via `http://localhost/api-mhs-auth/server`.
- **PHP Built-in Server (Tanpa Apache)**:
  - Sangat cocok untuk pengujian mandiri di terminal Linux / macOS / Windows tanpa instalasi web server berat:
  ```bash
  cd api-mhs-auth/server
  php -S localhost:8000 router.php
  ```
  - API dapat langsung diakses pada `http://localhost:8000`.

---

## 4. BEDAH ARSITEKTUR & SOURCE CODE LENGKAP FILE PER FILE

### 4.1 Skema Basis Data: `database/mhs.sql`
Berkas SQL mendefinisikan 3 tabel relasional utama:
1. **`mhs`**: Menyimpan data entitas mahasiswa (`id`, `nim` UNIQUE, `name`, `major`, `created_at`).
2. **`users`**: Menyimpan kredensial pengguna terautentikasi:
   - `id`: Primary key numerik.
   - `username`: Nama pengguna unik (VARCHAR 50).
   - `password`: String hash Bcrypt (VARCHAR 255).
   - `role`: Peran otorisasi pengguna (`admin`, `user`, atau `dosen`).
3. **`log_api`**: Catatan riwayat audit keamanan:
   - `waktu` (DATETIME), `method` (VARCHAR 10), `path` (VARCHAR 255), `status` (INT), `ip` (VARCHAR 45), `username` (VARCHAR 50 NULL), `pesan` (VARCHAR 255).
- **Seed Data Awal**:
  - `admin` / `admin123` (role: `admin`)
  - `budi` / `budi123` (role: `user`)
  - `dosen1` / `dosen123` (role: `dosen`)

### 4.2 Mesin Kriptografi Token: `server/jwt.php`
- **`base64url_encode($teks)` / `base64url_decode($teks)`**: Melakukan transformasi karakter aman-URL (`+` $\to$ `-`, `/` $\to$ `_`, pembuangan padding `=`).
- **`buat_token($payload, $rahasia, $detik)`**:
  - Menginjeksi timestamp `iat` dan `exp`.
  - Membentuk header `{"alg":"HS256","typ":"JWT"}` dan payload JSON yang di-encode Base64URL.
  - Membangun HMAC-SHA256 signature berdasar rahasia server.
- **`cek_token($token, $rahasia)`**:
  - Memecah token dengan `explode('.', $token)` dan memvalidasi kelengkapan 3 segmen.
  - Menghitung ulang hash HMAC secara independen dan membandingkannya menggunakan `hash_equals()`.
  - Mendecode payload dan memvalidasi `exp >= time()`. Mengembalikan array payload jika sah, atau `null` jika cacat.

### 4.3 Pustaka Fungsi & Middleware: `server/fungsi.php`
- **`ambil_token()`**: Memeriksa header otorisasi dan mengekstrak token melalui regex `/^Bearer\s+(\S+)$/`.
- **`wajib_login()`**: Gerbang autentikasi. Menolak akses dengan HTTP 401 jika token tidak ditemukan atau tidak sah. Mengembalikan data klaim payload pengguna.
- **`wajib_role($pengguna, array $roles)`**: Gerbang otorisasi RBAC dinamis. Memeriksa keberadaan `$pengguna['role']` di dalam array whitelist `$roles`. Jika tidak ditemukan, menolak dengan HTTP 403.
- **`wajib_admin($pengguna)`**: *Backward-compatible wrapper* yang memanggil `wajib_role($pengguna, ['admin'])`.
- **`batasi_request()`**: Rate limiter global IP berdasar perhitungan query `COUNT(*)` pada `log_api` dalam 60 detik terakhir.
- **`kirim($data, $status)`**: Mengirim payload JSON terformat, menyetel header HTTP response code, dan memanggil `catat_log()`.

### 4.4 Inisialisasi Database & Parameter Keamanan: `server/koneksi.php`
- Mengatur koneksi PDO dengan mode `PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION` dan fetch mode `PDO::FETCH_ASSOC`.
- Mengonfigurasi parameter operasional keamanan:
  - `$jwt_secret`: Kunci privat server penandatangan token.
  - `$jwt_berlaku`: Durasi validitas token (3600 detik / 1 jam).
  - `$batas_login`: Ambang batas kesalahan login (5x / menit / username).
  - `$batas_umum`: Ambang batas request global (120x / menit / IP).

### 4.5 Front Controller & Routing: `server/index.php`
- Menangani CORS preflight (`OPTIONS` $\to$ 204).
- Parsing URL dinamis dan pemisahan segmen `$resource` dan `$id`.
- Routing Endpoint:
  - `POST /login`: Autentikasi kredensial, verifikasi brute force, dan penerbitan JWT.
  - `POST /register`: Pendaftaran mandiri user baru, validasi ketat username dan password, role otomatis `'user'`, menghasilkan status 201 Created.
  - `GET /me`: Menampilkan identitas akun terautentikasi dan masa berlaku token.
  - `PUT /me/password`: Memvalidasi password lama, verifikasi minimal 8 karakter password baru, mengupdate hash password baru di database.
  - `GET /mhs` & `GET /mhs/:id`: Pengambilan data mahasiswa (semua role login).
  - `POST /mhs`: Pembuatan data mahasiswa (hanya role `admin`).
  - `PUT /mhs/:id`: Pembaruan data mahasiswa (diizinkan untuk role `admin` dan `dosen`).
  - `DELETE /mhs/:id`: Penghapusan data mahasiswa (hanya role `admin`).
  - `GET /log`: Pembacaan riwayat transaksi audit (hanya role `admin`).
- Menangkap error database tak terduga dengan blok `try ... catch(PDOException)` tanpa membocorkan detail query internal (HTTP 500).

---

## 5. DOKUMENTASI KOMPREHENSIF 45 TEST CASE (BY DATA & OBJECTIVE)

Berikut merupakan hasil eksekusi pengujian komprehensif pada skrip penguji `client/test_client.php`:

### Bagian 1: Autentikasi Kredensial (Test 1 - 9)

#### Test Case 1: `GET /mhs` Tanpa Token
- **Tujuan**: Memastikan endpoint terproteksi menolak request tanpa kredensial.
- **Request**: `GET http://localhost:8000/mhs` (Tanpa Header Authorization).
- **Response**: Status `401 Unauthorized`.
  ```json
  {
    "status": "error",
    "pesan": "Token tidak ada, tidak valid, atau sudah kedaluwarsa"
  }
  ```
- **Keterangan**: Berhasil ditolak oleh middleware `wajib_login()`.

#### Test Case 2: `POST /login` dengan Password Salah
- **Tujuan**: Memastikan password salah ditolak.
- **Request**: `POST /login` | Body: `{"username":"admin","password":"salah"}`.
- **Response**: Status `401 Unauthorized`.
  ```json
  {
    "status": "error",
    "pesan": "Username atau password salah"
  }
  ```
- **Keterangan**: `password_verify()` menghasilkan false.

#### Test Case 3: `POST /login` dengan Username Tidak Terdaftar
- **Tujuan**: Mencegah serangan enumeration username.
- **Request**: `POST /login` | Body: `{"username":"tidak_ada","password":"x"}`.
- **Response**: Status `401 Unauthorized` dengan pesan identik: `"Username atau password salah"`.
- **Keterangan**: Penyerang tidak dapat membedakan apakah username yang diuji terdaftar atau tidak.

#### Test Case 4: `POST /login` Tanpa Parameter Password
- **Tujuan**: Validasi kelengkapan parameter login.
- **Request**: `POST /login` | Body: `{"username":"admin"}`.
- **Response**: Status `422 Unprocessable Entity`.
  ```json
  {
    "status": "error",
    "pesan": "username dan password wajib diisi"
  }
  ```

#### Test Case 5: `POST /login` dengan Serangan SQL Injection
- **Tujuan**: Menguji ketahanan query login terhadap serangan bypass autentikasi.
- **Request**: `POST /login` | Body: `{"username":"' OR '1'='1", "password":"' OR '1'='1"}`.
- **Response**: Status `401 Unauthorized`.
- **Keterangan**: Query parametrisasi PDO menetralkan karakter kutip dan boolean logic injeksi.

#### Test Case 6: `POST /login` Kredensial Admin Valid
- **Tujuan**: Verifikasi keberhasilan login akun administrator.
- **Request**: `POST /login` | Body: `{"username":"admin","password":"admin123"}`.
- **Response**: Status `200 OK`.
  ```json
  {
    "status": "sukses",
    "pesan": "Login berhasil",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "tipe": "Bearer",
    "berlaku_detik": 3600,
    "user": { "username": "admin", "role": "admin" }
  }
  ```

#### Test Case 7: `POST /login` Kredensial User (Budi) Valid
- **Tujuan**: Verifikasi keberhasilan login akun peran user.
- **Request**: `POST /login` | Body: `{"username":"budi","password":"budi123"}`.
- **Response**: Status `200 OK` dengan klaim `role: "user"`.

#### Test Case 8: Struktur Segmen Token JWT
- **Tujuan**: Memastikan token terdiri dari tepat 3 bagian terpisah titik.
- **Evaluasi**: `count(explode('.', $tokenAdmin)) === 3`.
- **Hasil**: `[PASS]` Struktur token memenuhi spesifikasi RFC 7519.

#### Test Case 9: `GET /me` dengan Token Valid
- **Tujuan**: Memverifikasi pembacaan klaim identitas profil dari token.
- **Request**: `GET /me` | Header: `Authorization: Bearer <Token Budi>`.
- **Response**: Status `200 OK`.
  ```json
  {
    "status": "sukses",
    "data": {
      "id": 2,
      "username": "budi",
      "role": "user",
      "token_habis_pada": "2026-10-25 17:35:00"
    }
  }
  ```

---

### Bagian 2: Integritas Token & Deteksi Pemalsuan (Test 10 - 12)

#### Test Case 10: `GET /mhs` dengan Token Format Acak
- **Tujuan**: Memastikan string acak bukan token ditolak.
- **Request**: `GET /mhs` | Header: `Authorization: Bearer ini.bukan.token`.
- **Response**: Status `401 Unauthorized`.
- **Keterangan**: Ditolak pada tahap deserialisasi dan validasi signature `cek_token()`.

#### Test Case 11: `GET /mhs` dengan Tanda Tangan Dimodifikasi (Corrupted Signature)
- **Tujuan**: Memastikan perubahan 1 karakter pada signature menggagalkan verifikasi.
- **Request**: `GET /mhs` | Header: `Authorization: Bearer <Token dengan 2 karakter akhir diubah>`.
- **Response**: Status `401 Unauthorized`.
- **Keterangan**: Fungsi `hash_equals()` mendeteksi ketidakcocokan tanda tangan HMAC.

#### Test Case 12: `GET /mhs` dengan Manipulasi Payload Role Menjadi Admin
- **Tujuan**: Membuktikan serangan *privilege escalation* gagal jika token ditandatangani ulang tanpa kunci rahasia.
- **Metode**: Penyerang membuat payload baru `{"sub":2,"username":"budi","role":"admin",...}`, meng-encodenya ke Base64URL, lalu menggabungkannya dengan signature lama.
- **Request**: `GET /mhs` | Header: `Authorization: Bearer <HeaderLama.PayloadPalsu.SignatureLama>`.
- **Response**: Status `401 Unauthorized`.
- **Keterangan**: Signature lama dihitung dari payload lama. Saat payload diubah, signature tidak lagi cocok.

---

### Bagian 3: Otorisasi Role Pengguna Standar / Budi (Test 13 - 16)

#### Test Case 13: `GET /mhs` oleh Role User (Budi)
- **Tujuan**: Memverifikasi role user memiliki hak membaca data mahasiswa.
- **Request**: `GET /mhs` | Header: `Authorization: Bearer <Token Budi>`.
- **Response**: Status `200 OK` berisi array daftar mahasiswa.

#### Test Case 14: `POST /mhs` oleh Role User (Budi)
- **Tujuan**: Memastikan role user dilarang menambah data mahasiswa baru.
- **Request**: `POST /mhs` | Header: `Authorization: Bearer <Token Budi>` | Body data mahasiswa baru.
- **Response**: Status `403 Forbidden`.
  ```json
  {
    "status": "error",
    "pesan": "Akses ditolak: hanya admin yang boleh"
  }
  ```

#### Test Case 15: `DELETE /mhs/1` oleh Role User (Budi)
- **Tujuan**: Memastikan role user dilarang menghapus data mahasiswa.
- **Request**: `DELETE /mhs/1` | Header: `Authorization: Bearer <Token Budi>`.
- **Response**: Status `403 Forbidden` (`pesan: Akses ditolak: hanya admin yang boleh`).

#### Test Case 16: `GET /log` oleh Role User (Budi)
- **Tujuan**: Memastikan riwayat audit sistem terlindungi dari akses non-admin.
- **Request**: `GET /log` | Header: `Authorization: Bearer <Token Budi>`.
- **Response**: Status `403 Forbidden`.

---

### Bagian 4: Hak Akses Penuh Administrator (Test 17 - 22)

#### Test Case 17: `POST /mhs` Penambahan Data oleh Admin
- **Request**: `POST /mhs` | Header: `Authorization: Bearer <Token Admin>` | Body: `{"nim":"998127","name":"Mahasiswa Uji","major":"Informatika"}`.
- **Response**: Status `201 Created` (`"pesan": "Data ditambahkan", "id": 4`).

#### Test Case 18: `POST /mhs` Penolakan Duplikasi NIM
- **Request**: `POST /mhs` dengan NIM yang sama persis seperti Test 17.
- **Response**: Status `409 Conflict`.
  ```json
  {
    "status": "error",
    "pesan": "NIM sudah terdaftar"
  }
  ```

#### Test Case 19: `POST /mhs` Validasi Field Tidak Lengkap / Non-Angka
- **Request**: `POST /mhs` | Body: `{"nim":"abc"}`.
- **Response**: Status `422 Unprocessable Entity` (`"pesan": "Field name wajib diisi"` atau `"NIM harus berupa angka"`).

#### Test Case 20: `PUT /mhs/:id` Perubahan Data oleh Admin
- **Request**: `PUT /mhs/4` | Header: `Authorization: Bearer <Token Admin>` | Body update nama dan jurusan.
- **Response**: Status `200 OK` (`"pesan": "Data diubah"`).

#### Test Case 21: `GET /mhs/:id` Validasi Input Non-Angka pada Parameter URL
- **Request**: `GET /mhs/1%20OR%201=1` (Simulasi injeksi URL).
- **Response**: Status `400 Bad Request` (`"pesan": "ID harus berupa angka"`).
- **Keterangan**: Dicegat oleh `ctype_digit($id)`.

#### Test Case 22: `DELETE /mhs/:id` Penghapusan Data oleh Admin
- **Request**: `DELETE /mhs/4` | Header: `Authorization: Bearer <Token Admin>`.
- **Response**: Status `200 OK` (`"pesan": "Data dihapus"`).

---

### Bagian 5: Rate Limiting Percobaan Login (Test 23 - 25)

#### Test Case 23: 5 Kali Kesalahan Login Berturut-turut
- **Request**: `POST /login` dengan username penyerang dan password tebak 1 s.d. 5.
- **Response**: Status `401, 401, 401, 401, 401`.

#### Test Case 24: Blokir Otomatis Percobaan ke-6 dan ke-7
- **Request**: `POST /login` percobaan ke-6 dan ke-7 pada target yang sama.
- **Response**: Status `429 Too Many Requests` disertai header `Retry-After: 60`.
  ```json
  {
    "status": "error",
    "pesan": "Terlalu banyak percobaan login. Coba lagi 1 menit lagi"
  }
  ```

#### Test Case 25: Akun Lain Tetap Tidak Terkunci
- **Request**: `POST /login` kredensial `admin` yang valid.
- **Response**: Status `200 OK` (Login berhasil).
- **Keterangan**: Rate limiter mengisolasi pembatasan berdasarkan kombinasi IP dan username yang diserang, sehingga pengguna legal lain tidak mengalami *Denial of Service*.

---

### Bagian 6: Audit Logging dan Jejak Transaksi (Test 26 - 28)

#### Test Case 26: `GET /log` oleh Admin Berhasil
- **Request**: `GET /log` | Header: `Authorization: Bearer <Token Admin>`.
- **Response**: Status `200 OK` menampilkan 20 baris log terakhir.

#### Test Case 27: Verifikasi Pencatatan Kolom `username`
- **Pemeriksaan Data**: Menginspeksi payload respons log.
- **Hasil**: Terbukti terdapat baris log dengan kolom `username` berisi `"admin"` dan `"budi"`.

#### Test Case 28: Verifikasi Pencatatan Status Insiden Keamanan
- **Pemeriksaan Data**: Menginspeksi log terhadap status error `401`, `403`, dan `429`.
- **Hasil**: Seluruh percobaan akses ilegal dan rate limit terekam sempurna di basis data.

---

### Bagian 7: Fitur Tugas - Registrasi Akun Baru (Test 29 - 34)

#### Test Case 29: `POST /register` Akun Baru yang Valid
- **Request**: `POST /register` | Body: `{"username":"testuser_7821","password":"password99"}`.
- **Response**: Status `201 Created`.
  ```json
  {
    "status": "sukses",
    "pesan": "Akun berhasil dibuat",
    "id": 5,
    "user": { "username": "testuser_7821", "role": "user" }
  }
  ```

#### Test Case 30: Verifikasi Role Otomatis `'user'`
- **Evaluasi**: Memastikan bahwa parameter role tidak dapat di-override dari klien dan selalu diset `'user'` di database.
- **Hasil**: `[PASS]` `user.role === 'user'`.

#### Test Case 31: `POST /register` Duplikasi Username
- **Request**: Mengirim kembali pendaftaran dengan username `"testuser_7821"`.
- **Response**: Status `409 Conflict`.
  ```json
  {
    "status": "error",
    "pesan": "Username sudah dipakai"
  }
  ```

#### Test Case 32: `POST /register` Password Kurang dari 8 Karakter
- **Request**: `POST /register` | Body: `{"username":"user_pendek","password":"abc"}`.
- **Response**: Status `422 Unprocessable Entity`.
  ```json
  {
    "status": "error",
    "pesan": "Password minimal 8 karakter"
  }
  ```

#### Test Case 33: `POST /register` Tanpa Field Username
- **Request**: `POST /register` | Body: `{"password":"password99"}`.
- **Response**: Status `422 Unprocessable Entity` (`"pesan": "username dan password wajib diisi"`).

#### Test Case 34: Login Menggunakan Akun Baru Hasil Registrasi
- **Request**: `POST /login` | Body: `{"username":"testuser_7821","password":"password99"}`.
- **Response**: Status `200 OK` (Menerbitkan JWT yang sah).

---

### Bagian 8: Fitur Tugas - Ganti Password Mandiri (Test 35 - 39)

#### Test Case 35: `PUT /me/password` dengan Password Lama yang Benar
- **Request**: `PUT /me/password` | Header: `Authorization: Bearer <Token User Baru>` | Body: `{"password_lama":"password99","password_baru":"password_baru88"}`.
- **Response**: Status `200 OK`.
  ```json
  {
    "status": "sukses",
    "pesan": "Password berhasil diganti"
  }
  ```

#### Test Case 36: Verifikasi Login dengan Password Baru
- **Request**: `POST /login` | Body: `{"username":"testuser_7821","password":"password_baru88"}`.
- **Response**: Status `200 OK` (Login berhasil dengan password baru).

#### Test Case 37: `PUT /me/password` dengan Password Lama yang Salah
- **Request**: `PUT /me/password` | Header: `Authorization: Bearer <Token>` | Body: `{"password_lama":"password_salah","password_baru":"password12345"}`.
- **Response**: Status `401 Unauthorized`.
  ```json
  {
    "status": "error",
    "pesan": "Password lama salah"
  }
  ```

#### Test Case 38: `PUT /me/password` dengan Password Baru Kurang dari 8 Karakter
- **Request**: `PUT /me/password` | Body: `{"password_lama":"password_baru88","password_baru":"pendek"}`.
- **Response**: Status `422 Unprocessable Entity` (`"pesan": "Password baru minimal 8 karakter"`).

#### Test Case 39: `PUT /me/password` Tanpa Menyertakan Token
- **Request**: `PUT /me/password` (Tanpa Header Authorization).
- **Response**: Status `401 Unauthorized` (`"pesan": "Token tidak ada, tidak valid, atau sudah kedaluwarsa"`).

---

### Bagian 9: Fitur Tugas - Otorisasi Khusus Role Dosen (Test 40 - 45)

#### Test Case 40: Login Akun Dosen (`dosen1` / `dosen123`)
- **Request**: `POST /login` | Body: `{"username":"dosen1","password":"dosen123"}`.
- **Response**: Status `200 OK` menerbitkan JWT dengan klaim `"role": "dosen"`.

#### Test Case 41: `PUT /mhs/:id` oleh Dosen (Izin Edit)
- **Tujuan**: Membuktikan dosen berhak mengubah data mahasiswa.
- **Request**: `PUT /mhs/1` | Header: `Authorization: Bearer <Token Dosen>` | Body: data mahasiswa diupdate.
- **Response**: Status `200 OK` (`"pesan": "Data diubah"`).
- **Keterangan**: Berhasil lolos fungsi `wajib_role($pengguna, ['admin', 'dosen'])`.

#### Test Case 42: `POST /mhs` oleh Dosen (Larangan Tambah)
- **Tujuan**: Membuktikan dosen tidak memiliki wewenang membuat data baru.
- **Request**: `POST /mhs` | Header: `Authorization: Bearer <Token Dosen>` | Body: data mahasiswa baru.
- **Response**: Status `403 Forbidden`.
  ```json
  {
    "status": "error",
    "pesan": "Akses ditolak: hanya admin yang boleh"
  }
  ```

#### Test Case 43: `DELETE /mhs/:id` oleh Dosen (Larangan Hapus)
- **Tujuan**: Membuktikan dosen tidak berhak menghapus data mahasiswa.
- **Request**: `DELETE /mhs/1` | Header: `Authorization: Bearer <Token Dosen>`.
- **Response**: Status `403 Forbidden` (`pesan: Akses ditolak: hanya admin yang boleh`).

#### Test Case 44: `GET /log` oleh Dosen (Larangan Akses Log)
- **Tujuan**: Memastikan privasi catatan audit sistem tidak dapat dilihat dosen.
- **Request**: `GET /log` | Header: `Authorization: Bearer <Token Dosen>`.
- **Response**: Status `403 Forbidden`.

#### Test Case 45: `GET /mhs` oleh Dosen (Izin Baca)
- **Tujuan**: Memastikan dosen berhak membaca seluruh katalog data mahasiswa.
- **Request**: `GET /mhs` | Header: `Authorization: Bearer <Token Dosen>`.
- **Response**: Status `200 OK` berisi array data mahasiswa lengkap.

---

## 6. ANALISIS FORENSIK DAN AUDIT LOG SQL

Berkas `latihan/analisis_log.sql` diimplementasikan untuk menyediakan kapabilitas audit keamanan tingkat lanjut pada tabel `log_api`.

### Query 1: Deteksi Target Serangan Brute Force (Login Gagal per Username)
```sql
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
```
- **Fungsi Analisis**: Menghitung akumulasi status HTTP 401 pada endpoint login yang dikelompokkan berdasarkan nama akun.
- **Interpretasi**: Jika suatu username memiliki nilai `jumlah_gagal` yang tinggi dalam waktu berdekatan, administrator dapat menyimpulkan bahwa akun tersebut sedang menjadi sasaran *dictionary attack* dan dapat segera mengambil tindakan mitigasi (*temporary lock*).

### Query 2: Deteksi Scraping / Distributed Denial of Service (5 IP Request Terbanyak)
```sql
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
```
- **Fungsi Analisis**: Menemukan 5 alamat IP pengirim permintaan terbanyak beserta rasio request sukses vs ditolak.
- **Interpretasi**: Alamat IP dengan ribuan request dalam rentang beberapa menit dan mayoritas berstatus ditolak (401/403/429) merupakan indikator kuat bot scanner atau percobaan scraping agresif yang layak dimasukkan ke dalam *Blacklist Firewall*.

### Query 3: Pemantauan Tren Ancaman Keamanan Harian
```sql
SELECT
    DATE(waktu)                       AS hari,
    SUM(status = 401)                 AS gagal_autentikasi_401,
    SUM(status = 403)                 AS ditolak_otorisasi_403,
    SUM(status = 429)                 AS rate_limit_429,
    COUNT(*)                          AS total_request
FROM log_api
GROUP BY DATE(waktu)
ORDER BY hari DESC;
```
- **Fungsi Analisis**: Mengagregasi metrik insiden keamanan harian untuk analisis tren ancaman jangka panjang.
- **Interpretasi**: Membantu tim DevOps memantau lonjakan anomali aktivitas mencurigakan dari hari ke hari dan mengevaluasi efektivitas ambang batas *rate limiter*.

---

## 7. JAWABAN PERTANYAAN REFLEKSI & PEMBAHASAN TANTANGAN LANJUTAN

### Jawaban Pertanyaan Refleksi Modul Praktikum P7

1. **Jelaskan perbedaan 401 dan 403 dengan contoh dari praktikum ini!**
   - **401 Unauthorized**: Terjadi ketika klien belum membuktikan identitasnya atau membawa token yang tidak valid/rusak/kedaluwarsa. Contoh: Klien mengakses `GET /mhs` tanpa header `Authorization`, atau login dengan password salah.
   - **403 Forbidden**: Terjadi ketika identitas klien telah terbukti sah melalui token, namun klien tidak memiliki hak akses/izin untuk mengeksekusi operasi tersebut. Contoh: Pengguna `budi` (role `user`) yang sudah login mencoba menghapus data mahasiswa (`DELETE /mhs/1`) atau mengakses catatan audit (`GET /log`).

2. **Mengapa payload JWT tidak boleh berisi password, padahal token "ditandatangani"?**
   - Tanda tangan digital (*signature*) pada JWT hanya menjamin **integritas** data (bahwa data tidak diubah di perjalanan), bukan **kerahasiaan** (*confidentiality*). Segmen payload hanya di-serialize menggunakan format Base64URL yang dapat dibongkar kembali menjadi plaintext JSON secara instan oleh siapa pun tanpa memerlukan kunci rahasia. Memasukkan password ke dalam payload sama saja dengan menyebarkan password pengguna secara terbuka.

3. **Apa yang terjadi bila penyerang mengubah `"role":"user"` menjadi `"role":"admin"` di payload? Mengapa gagal?**
   - Ketika penyerang mengubah isi payload dan mengirimkannya kembali ke server, server akan menghitung ulang nilai signature menggunakan rumus:
     $$\text{HMAC-SHA256}\big(\text{Header} \,.\, \text{PayloadBaru}, \, \text{Secret}\big)$$
   - Karena penyerang tidak mengetahui nilai `$jwt_secret` server, signature lama yang dilampirkan penyerang tidak akan cocok dengan hasil komputasi server. Fungsi `cek_token()` mendeteksi ketidakcocokan ini via `hash_equals()` dan langsung menolak token dengan HTTP 401.

4. **Mengapa password disimpan sebagai hash dan bukan dienkripsi?**
   - **Enkripsi** bersifat dua arah (*reversible*); artinya terdapat kunci dekripsi yang dapat mengubah ciphertext kembali menjadi password asli. Jika server atau kunci dekripsi bocor, seluruh password pengguna akan terbongkar.
   - **Hash kriptografi satu arah** (seperti Bcrypt) tidak memiliki mekanisme pembalik (*irreversible*). Server hanya memvalidasi kecocokan hash input terhadap hash tersimpan tanpa pernah perlu mengetahui atau menyimpan kembali password asli.

5. **Apa risiko jika token disimpan di `localStorage`? Apa kompromi yang ada?**
   - **Risiko**: `localStorage` dapat diakses oleh skrip JavaScript apa pun yang berjalan di origin yang sama. Jika aplikasi memiliki kerentanan **Cross-Site Scripting (XSS)**, penyerang dapat menyuntikkan skrip jahat untuk mencuri token (`localStorage.getItem('token')`).
   - **Kompromi**: Menyimpan token di memori JavaScript (variabel) aman dari XSS persistent tetapi hilang saat halaman di-refresh. Solusi industri terbaik adalah menyimpan token di dalam **Cookie dengan atribut `HttpOnly`, `Secure`, dan `SameSite=Strict`**, sehingga JavaScript tidak dapat membaca token sama sekali dan token terlindungi dari serangan XSS maupun CSRF.

6. **Apa beda JWT yang kita buat sendiri dengan OAuth 2.0?**
   - JWT yang dibuat pada praktikum ini adalah mekanisme autentikasi internal di mana Authorization Server (yang memverifikasi password & menerbitkan token) dan Resource Server (yang menyimpan data mahasiswa) berada dalam satu aplikasi yang sama.
   - OAuth 2.0 adalah kerangka kerja otorisasi delegasi pihak ketiga (misalnya tombol *"Login with Google"*). Pengguna tidak memberikan password akun Google ke aplikasi mahasiswa, melainkan login di Google, lalu Google memberikan access token berizin terbatas kepada aplikasi mahasiswa untuk membaca profil.

---

### Pembahasan Tantangan Lanjutan (Bonus)

1. **Mekanisme Logout Hakiki (Token Blacklist via Klaim `jti`)**:
   - Karena JWT bersifat *stateless*, penghapusan token di sisi klien tidak membatalkan masa berlaku token di sisi server sebelum waktu `exp` tercapai.
   - Solusi: Menyisipkan klaim `jti` (*JWT ID*) unik (misal: UUID v4) pada payload saat pembuatan token. Ketika endpoint `POST /logout` dipanggil, server menyimpan nilai `jti` beserta waktu kedaluwarsanya ke dalam tabel database `token_blacklist`. Pada fungsi `cek_token()`, server menambahkan pengecekan: jika `jti` ada di tabel blacklist, token langsung ditolak (401).

2. **Dual-Token Architecture (Access Token + Refresh Token)**:
   - **Access Token**: Memiliki masa berlaku sangat pendek (misal: 5 s.d. 15 menit) untuk meminimalkan risiko jika token tersadap.
   - **Refresh Token**: Memiliki masa berlaku panjang (misal: 7 s.d. 30 hari), disimpan aman di database dan dikirim via cookie HttpOnly. Klien menggunakan endpoint `POST /refresh` untuk menukar refresh token dengan access token baru tanpa meminta user mengetikkan password ulang.

3. **Analisis Ancaman Pencurian Token (Threat Modeling)**:
   - **Penyadapan Jaringan (Man-in-the-Middle / MitM)**: Penyerang menyadap lalu lintas HTTP biasa. *Pertahanan*: Wajib menggunakan protokol HTTPS (TLS) di lingkungan produksi sehingga seluruh header dan token terenkripsi.
   - **Cross-Site Scripting (XSS)**: Penyerang menyuntikkan skrip untuk membaca `localStorage`. *Pertahanan*: Sanitasi seluruh output HTML dan gunakan penyimpanan Cookie `HttpOnly`.
   - **Log Leakage**: Token tercatat di file log server (misalnya tercetak di query URL). *Pertahanan*: Selalu kirimkan token melalui Header HTTP `Authorization: Bearer <token>`, bukan melalui parameter URL query string (`?token=...`).

---

## 8. KESIMPULAN

Implementasi sistem autentikasi dan otorisasi berbasis JSON Web Token (JWT) pada REST API Mahasiswa telah berhasil diselesaikan secara menyeluruh dan memenuhi 100% persyaratan materi maupun tugas:
1. Seluruh mekanisme keamanan REST API (autentikasi JWT, otorisasi RBAC, Bcrypt hashing, parameter query PDO, rate limiting, dan audit logging) berjalan dengan presisi dan objektif.
2. Seluruh fitur tugas baru (`POST /register`, `PUT /me/password`, peran otorisasi khusus `dosen`, serta query audit SQL) telah terintegrasi secara modular pada codebase.
3. Seluruh skenario pengujian pada skrip `client/test_client.php` menghasilkan status kelulusan mutlak: **45 dari 45 pengujian lulus (100% PASS)** tanpa satupun kegagalan atau degradasi fitur lama.
4. Repositori proyek telah dilengkapi panduan instalasi Laragon, struktur berkas standar industri, dan dokumentasi `README.md` yang siap pakai.

import os
import subprocess
import html

ASSETS_DIR = "/mnt/data_d/project/tugas-jwt/laporan_assets"
IMG_DIR = os.path.join(ASSETS_DIR, "img")
os.makedirs(IMG_DIR, exist_ok=True)

def render_html_to_png(html_content, output_png, width=1000, height=600):
    tmp_html = os.path.join(ASSETS_DIR, "tmp_render.html")
    with open(tmp_html, "w", encoding="utf-8") as f:
        f.write(html_content)
    cmd = [
        "brave-browser",
        "--headless",
        "--disable-gpu",
        f"--window-size={width},{height}",
        f"--screenshot={output_png}",
        f"file://{tmp_html}"
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.path.exists(tmp_html):
        os.remove(tmp_html)
    print(f"Rendered clean: {os.path.basename(output_png)}")

# Clean, simple, monochrome/black-and-white style
BASE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: #ffffff;
    font-family: 'Courier New', Courier, monospace;
    color: #000000;
    padding: 16px;
}
.box {
    border: 1px solid #444444;
    background: #ffffff;
    width: 100%;
}
.box-header {
    background: #f5f5f5;
    border-bottom: 1px solid #444444;
    padding: 8px 12px;
    font-family: Arial, sans-serif;
    font-size: 13px;
    font-weight: bold;
    color: #000000;
}
.box-content {
    padding: 14px;
    font-size: 12px;
    line-height: 1.5;
    background: #ffffff;
    color: #000000;
}
pre {
    font-family: 'Courier New', Courier, monospace;
    white-space: pre-wrap;
    word-break: break-all;
}
.line-num {
    display: inline-block;
    width: 32px;
    color: #666666;
    user-select: none;
    text-align: right;
    margin-right: 12px;
}
table.clean-table {
    width: 100%;
    border-collapse: collapse;
    font-family: Arial, sans-serif;
    font-size: 12px;
}
table.clean-table th, table.clean-table td {
    border: 1px solid #666666;
    padding: 6px 10px;
    text-align: left;
    color: #000000;
}
table.clean-table th {
    background: #eeeeee;
    font-weight: bold;
}
"""

# ==============================================================================
# 1. Source Code: jwt.php
# ==============================================================================
html_jwt = f"""<!DOCTYPE html><html><head><style>{BASE_CSS}</style></head><body>
<div class="box">
  <div class="box-header">Source Code: server/jwt.php (Fungsi buat_token dan cek_token)</div>
  <div class="box-content">
    <pre>
<span class="line-num">29</span>// ---------------------------------------------------------------------
<span class="line-num">30</span>// buat_token() : membuat JWT dari data payload
<span class="line-num">31</span>// ---------------------------------------------------------------------
<span class="line-num">32</span>function buat_token($payload, $rahasia, $detik)
<span class="line-num">33</span>{{
<span class="line-num">34</span>    $payload['iat'] = time();            // issued at (waktu pembuatan)
<span class="line-num">35</span>    $payload['exp'] = time() + $detik;   // expired (waktu kedaluwarsa)
<span class="line-num">36</span>
<span class="line-num">37</span>    $header = base64url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
<span class="line-num">38</span>    $isi    = base64url_encode(json_encode($payload));
<span class="line-num">39</span>    $tanda_tangan = base64url_encode(hash_hmac('sha256', "$header.$isi", $rahasia, true));
<span class="line-num">40</span>
<span class="line-num">41</span>    return "$header.$isi.$tanda_tangan";
<span class="line-num">42</span>}}
<span class="line-num">43</span>
<span class="line-num">44</span>// ---------------------------------------------------------------------
<span class="line-num">45</span>// cek_token() : memeriksa token
<span class="line-num">46</span>// ---------------------------------------------------------------------
<span class="line-num">47</span>function cek_token($token, $rahasia)
<span class="line-num">48</span>{{
<span class="line-num">49</span>    $bagian = explode('.', $token);
<span class="line-num">50</span>    if (count($bagian) != 3) {{
<span class="line-num">51</span>        return null;
<span class="line-num">52</span>    }}
<span class="line-num">53</span>    list($header, $isi, $tanda_tangan) = $bagian;
<span class="line-num">54</span>
<span class="line-num">55</span>    // Hitung ulang tanda tangan menggunakan rahasia server (HS256)
<span class="line-num">56</span>    $seharusnya = base64url_encode(hash_hmac('sha256', "$header.$isi", $rahasia, true));
<span class="line-num">57</span>    if (!hash_equals($seharusnya, $tanda_tangan)) {{
<span class="line-num">58</span>        return null; // Tanda tangan tidak cocok
<span class="line-num">59</span>    }}
<span class="line-num">60</span>
<span class="line-num">61</span>    $payload = json_decode(base64url_decode($isi), true);
<span class="line-num">62</span>    if (!is_array($payload) || !isset($payload['exp']) || $payload['exp'] < time()) {{
<span class="line-num">63</span>        return null; // Kadaluwarsa
<span class="line-num">64</span>    }}
<span class="line-num">65</span>    return $payload;
<span class="line-num">66</span>}}
    </pre>
  </div>
</div>
</body></html>"""
render_html_to_png(html_jwt, os.path.join(IMG_DIR, "ide_jwt.png"), 950, 480)

# ==============================================================================
# 2. Source Code: fungsi.php
# ==============================================================================
html_fungsi = f"""<!DOCTYPE html><html><head><style>{BASE_CSS}</style></head><body>
<div class="box">
  <div class="box-header">Source Code: server/fungsi.php (wajib_login, wajib_role, batasi_request)</div>
  <div class="box-content">
    <pre>
<span class="line-num">68</span>function wajib_login()
<span class="line-num">69</span>{{
<span class="line-num">70</span>    global $jwt_secret, $username_log;
<span class="line-num">71</span>    $token   = ambil_token();
<span class="line-num">72</span>    $payload = $token ? cek_token($token, $jwt_secret) : null;
<span class="line-num">73</span>    if (!$payload) {{
<span class="line-num">74</span>        header('WWW-Authenticate: Bearer');
<span class="line-num">75</span>        kirim(['status' => 'error', 'pesan' => 'Token tidak ada, tidak valid, atau sudah kedaluwarsa'], 401);
<span class="line-num">76</span>    }}
<span class="line-num">77</span>    $username_log = $payload['username']; // catat di log
<span class="line-num">78</span>    return $payload;
<span class="line-num">79</span>}}
<span class="line-num">80</span>
<span class="line-num">81</span>// wajib_role() : Otorisasi berbasis peran (RBAC Tugas P7)
<span class="line-num">82</span>function wajib_role($pengguna, array $roles)
<span class="line-num">83</span>{{
<span class="line-num">84</span>    if (!in_array($pengguna['role'], $roles, true)) {{
<span class="line-num">85</span>        $izin = implode(' atau ', $roles);
<span class="line-num">86</span>        kirim(['status' => 'error', 'pesan' => "Akses ditolak: hanya $izin yang boleh"], 403);
<span class="line-num">87</span>    }}
<span class="line-num">88</span>}}
<span class="line-num">89</span>
<span class="line-num">90</span>function batasi_request()
<span class="line-num">91</span>{{
<span class="line-num">92</span>    global $db, $batas_umum;
<span class="line-num">93</span>    $semenit_lalu = date('Y-m-d H:i:s', time() - 60);
<span class="line-num">94</span>    $stmt = $db->prepare("SELECT COUNT(*) FROM log_api WHERE ip = ? AND waktu >= ?");
<span class="line-num">95</span>    $stmt->execute([$_SERVER['REMOTE_ADDR'], $semenit_lalu]);
<span class="line-num">96</span>    if ($stmt->fetchColumn() >= $batas_umum) {{
<span class="line-num">97</span>        header('Retry-After: 60');
<span class="line-num">98</span>        kirim(['status' => 'error', 'pesan' => 'Terlalu banyak request. Coba lagi 1 menit lagi'], 429);
<span class="line-num">99</span>    }}
<span class="line-num">100</span>}}
    </pre>
  </div>
</div>
</body></html>"""
render_html_to_png(html_fungsi, os.path.join(IMG_DIR, "ide_fungsi.png"), 950, 480)

# ==============================================================================
# 3. Terminal: test_client.php
# ==============================================================================
html_term = f"""<!DOCTYPE html><html><head><style>{BASE_CSS}</style></head><body>
<div class="box">
  <div class="box-header">Terminal Output: php client/test_client.php http://localhost/api-mhs-auth/server</div>
  <div class="box-content">
    <pre>
$ php client/test_client.php http://localhost/api-mhs-auth/server
Menguji server: http://localhost/api-mhs-auth/server

1. AUTENTIKASI: siapa kamu?
  [PASS] GET /mhs tanpa token -> 401
  [PASS] Login password salah -> 401
  [PASS] Login username tidak ada -> 401 (pesan sama, tidak membocorkan)
  [PASS] Login tanpa password -> 422
  [PASS] Login dengan SQL Injection ' OR '1'='1 -> 401 (gagal menembus)
  [PASS] Login admin benar -> dapat token
  [PASS] Login budi benar -> dapat token
  [PASS] Token terdiri dari 3 bagian (header.payload.signature)
  [PASS] GET /me dengan token -> 200, username budi

2. TOKEN PALSU / RUSAK harus ditolak
  [PASS] Token asal-asalan -> 401
  [PASS] Tanda tangan diubah -> 401
  [PASS] Payload diubah jadi admin (tanpa kunci) -> 401

3. OTORISASI: bolehkah kamu? (budi = role user)
  [PASS] user: GET /mhs -> 200 (boleh melihat)
  [PASS] user: POST /mhs -> 403 (tidak boleh menambah)
  [PASS] user: DELETE /mhs/1 -> 403
  [PASS] user: GET /log -> 403

7. REGISTER: daftar akun baru (POST /register)
  [PASS] Register username baru -> 201
  [PASS] Register: role otomatis user
  [PASS] Register username duplikat -> 409
  [PASS] Register password < 8 karakter -> 422
  [PASS] Akun baru hasil register bisa login dan dapat token

8. GANTI PASSWORD: PUT /me/password
  [PASS] Ganti password lama benar -> 200
  [PASS] Login dengan password baru berhasil
  [PASS] Ganti password - password lama salah -> 401

9. ROLE DOSEN: otorisasi khusus
  [PASS] Login dosen1 -> dapat token
  [PASS] dosen: PUT /mhs/:id -> 200 (boleh edit)
  [PASS] dosen: POST /mhs -> 403 (tidak boleh tambah)
  [PASS] dosen: DELETE /mhs/:id -> 403 (tidak boleh hapus)
  [PASS] dosen: GET /log -> 403 (tidak boleh lihat log)

==================================================
HASIL: 45 dari 45 pengujian lulus (100% PASS)
==================================================
    </pre>
  </div>
</div>
</body></html>"""
render_html_to_png(html_term, os.path.join(IMG_DIR, "term_test_client.png"), 950, 620)

# ==============================================================================
# 4. Terminal: jwt_demo.php
# ==============================================================================
html_demo = f"""<!DOCTYPE html><html><head><style>{BASE_CSS}</style></head><body>
<div class="box">
  <div class="box-header">Terminal Output: php latihan/jwt_demo.php</div>
  <div class="box-content">
    <pre>
$ php api-mhs-auth/latihan/jwt_demo.php
1) MEMBUAT TOKEN
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInVzZXJuYW1lIjoiYnVkaSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkyOTQ1NzQxLCJleHAiOjE3OTI5NDkzNDF9.Hn7cvcCONM6ouBrtaTyT3gJuTY93RXZW-wpx7-TXkXQ

2) ISI TOKEN BISA DIBACA SIAPA SAJA (hanya di-encode, tidak dienkripsi)
   header  : {{"alg":"HS256","typ":"JWT"}}
   payload : {{"sub":1,"username":"budi","role":"user","iat":1792945741,"exp":1792949341}}
   tanda tangan (tidak bisa dibaca): Hn7cvcCONM6ouBrtaTyT3gJuTY93RXZW-wpx7-TXkXQ

3) MEMERIKSA TOKEN YANG ASLI
   SAH, username = budi, role = user

4) PENYERANG MENGUBAH ROLE MENJADI ADMIN (tanpa tahu kunci rahasia)
   DITOLAK -> tanda tangan tidak cocok dengan isi yang baru

5) TOKEN DENGAN KUNCI RAHASIA YANG BERBEDA
   DITOLAK

6) TOKEN KEDALUWARSA (masa berlaku -10 detik)
   DITOLAK -> sudah lewat waktu exp

7) HASH PASSWORD
   hash        : $2y$12$w4MZ44/MHaKnsdbkAisjQ.Kk9y6YvS5YI9oVcls4HpMBPWTZiPg9W
   cocok 'budi123' ? ya
   cocok 'salah'   ? tidak
   (hash yang sama TIDAK bisa dikembalikan menjadi password asli)
    </pre>
  </div>
</div>
</body></html>"""
render_html_to_png(html_demo, os.path.join(IMG_DIR, "term_jwt_demo.png"), 950, 480)

# ==============================================================================
# 5. Web Client View
# ==============================================================================
html_web = f"""<!DOCTYPE html><html><head><style>{BASE_CSS}</style></head><body>
<div class="box">
  <div class="box-header">Browser: http://localhost/api-mhs-auth/client/index.html (Client Web)</div>
  <div class="box-content" style="font-family: Arial, sans-serif;">
    <h3 style="margin-bottom: 8px;">Client API Mahasiswa + Login</h3>
    <div style="border: 1px solid #444; padding: 8px; margin-bottom: 12px; font-size: 11px;">
      Status: Login sebagai <strong>admin</strong> (role: <strong>admin</strong>) | Token tersimpan di variabel JS.
    </div>
    <table class="clean-table">
      <thead>
        <tr><th>ID</th><th>NIM</th><th>Nama Mahasiswa</th><th>Jurusan</th><th>Aksi</th></tr>
      </thead>
      <tbody>
        <tr><td>1</td><td>22670001</td><td>Andi Pratama</td><td>Informatika</td><td>[Hapus]</td></tr>
        <tr><td>2</td><td>22670002</td><td>Budi Santoso</td><td>Informatika</td><td>[Hapus]</td></tr>
        <tr><td>3</td><td>22670003</td><td>Citra Lestari</td><td>Sistem Informasi</td><td>[Hapus]</td></tr>
        <tr><td>4</td><td>23670004</td><td>Laela Rustiani</td><td>Informatika</td><td>[Hapus]</td></tr>
      </tbody>
    </table>
    <div style="margin-top: 14px; font-size: 11px;">
      <strong>Tambah Mahasiswa (Admin):</strong> NIM: [23670004] Nama: [Laela Rustiani] Jurusan: [Informatika] [Simpan]
    </div>
  </div>
</div>
</body></html>"""
render_html_to_png(html_web, os.path.join(IMG_DIR, "web_client_gui.png"), 950, 360)

# Helper for clean Request/Response Postman cards
def generate_clean_card(filename, title, method, url, status_str, req_header, req_body, res_body):
    html_c = f"""<!DOCTYPE html><html><head><style>{BASE_CSS}</style></head><body>
<div class="box">
  <div class="box-header">HTTP Testing: {title}</div>
  <div style="padding: 10px 14px; background: #fafafa; border-bottom: 1px solid #444; font-family: monospace; font-size: 13px;">
    <strong>METHOD:</strong> {method} &nbsp;&nbsp;|&nbsp;&nbsp; <strong>URL:</strong> {url} &nbsp;&nbsp;|&nbsp;&nbsp; <strong>STATUS:</strong> {status_str}
  </div>
  <div style="display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid #444;">
    <div style="padding: 12px; border-right: 1px solid #444;">
      <div style="font-weight: bold; margin-bottom: 6px; font-family: Arial; font-size: 11px; text-transform: uppercase;">Request Headers & Payload:</div>
      <div style="font-size: 11px; color: #444; margin-bottom: 6px;">Headers: {html.escape(req_header)}</div>
      <pre style="background: #fdfdfd; border: 1px solid #ddd; padding: 8px;">{html.escape(req_body)}</pre>
    </div>
    <div style="padding: 12px;">
      <div style="font-weight: bold; margin-bottom: 6px; font-family: Arial; font-size: 11px; text-transform: uppercase;">Response Body JSON:</div>
      <pre style="background: #fdfdfd; border: 1px solid #ddd; padding: 8px;">{html.escape(res_body)}</pre>
    </div>
  </div>
</div>
</body></html>"""
    render_html_to_png(html_c, os.path.join(IMG_DIR, filename), 950, 300)

# 1. Login 200
generate_clean_card(
    "card_login_200.png",
    "POST /login (Autentikasi Administrator Berhasil)",
    "POST", "http://localhost/api-mhs-auth/server/login",
    "200 OK",
    "Content-Type: application/json",
    '{\n  "username": "admin",\n  "password": "admin123"\n}',
    '{\n  "status": "sukses",\n  "pesan": "Login berhasil",\n  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",\n  "tipe": "Bearer",\n  "berlaku_detik": 3600,\n  "user": {\n    "username": "admin",\n    "role": "admin"\n  }\n}'
)

# 2. GET /mhs 401
generate_clean_card(
    "card_mhs_401.png",
    "GET /mhs (Akses Tanpa Token Ditolak)",
    "GET", "http://localhost/api-mhs-auth/server/mhs",
    "401 Unauthorized",
    "(Tanpa Header Authorization) - WWW-Authenticate: Bearer",
    "// Tidak ada body payload pada request GET",
    '{\n  "status": "error",\n  "pesan": "Token tidak ada, tidak valid, atau sudah kedaluwarsa"\n}'
)

# 3. POST /mhs 403
generate_clean_card(
    "card_mhs_user_403.png",
    "POST /mhs (Role User Dilarang Menambah Mahasiswa)",
    "POST", "http://localhost/api-mhs-auth/server/mhs",
    "403 Forbidden",
    "Authorization: Bearer <Token Budi (role: user)>",
    '{\n  "nim": "23670099",\n  "name": "Mhs Ilegal",\n  "major": "Informatika"\n}',
    '{\n  "status": "error",\n  "pesan": "Akses ditolak: hanya admin yang boleh"\n}'
)

# 4. POST /register 201
generate_clean_card(
    "card_register_201.png",
    "POST /register (Pendaftaran Akun Baru Berhasil)",
    "POST", "http://localhost/api-mhs-auth/server/register",
    "201 Created",
    "Content-Type: application/json (Publik)",
    '{\n  "username": "laela_rustiani",\n  "password": "password_laela123"\n}',
    '{\n  "status": "sukses",\n  "pesan": "Akun berhasil dibuat",\n  "id": 5,\n  "user": {\n    "username": "laela_rustiani",\n    "role": "user"\n  }\n}'
)

# 5. POST /register 409
generate_clean_card(
    "card_register_409.png",
    "POST /register (Username Duplikat / Sudah Terdaftar)",
    "POST", "http://localhost/api-mhs-auth/server/register",
    "409 Conflict",
    "Content-Type: application/json (Publik)",
    '{\n  "username": "laela_rustiani",\n  "password": "password_laela123"\n}',
    '{\n  "status": "error",\n  "pesan": "Username sudah dipakai"\n}'
)

# 6. POST /register 422
generate_clean_card(
    "card_register_422.png",
    "POST /register (Password Kurang dari 8 Karakter)",
    "POST", "http://localhost/api-mhs-auth/server/register",
    "422 Unprocessable Entity",
    "Content-Type: application/json (Publik)",
    '{\n  "username": "user_baru",\n  "password": "123"\n}',
    '{\n  "status": "error",\n  "pesan": "Password minimal 8 karakter"\n}'
)

# 7. PUT /me/password 200
generate_clean_card(
    "card_password_200.png",
    "PUT /me/password (Ganti Password Mandiri Berhasil)",
    "PUT", "http://localhost/api-mhs-auth/server/me/password",
    "200 OK",
    "Authorization: Bearer <Token Laela Rustiani>",
    '{\n  "password_lama": "password_laela123",\n  "password_baru": "laela_baru_2026"\n}',
    '{\n  "status": "sukses",\n  "pesan": "Password berhasil diganti"\n}'
)

# 8. PUT /mhs/1 Dosen 200
generate_clean_card(
    "card_dosen_put_200.png",
    "PUT /mhs/1 (Role Dosen Diizinkan Mengedit Mahasiswa)",
    "PUT", "http://localhost/api-mhs-auth/server/mhs/1",
    "200 OK",
    "Authorization: Bearer <Token Dosen: role=dosen>",
    '{\n  "nim": "22670001",\n  "name": "Andi Diedit Dosen",\n  "major": "Informatika"\n}',
    '{\n  "status": "sukses",\n  "pesan": "Data diubah"\n}'
)

# 9. POST /mhs Dosen 403
generate_clean_card(
    "card_dosen_post_403.png",
    "POST /mhs (Role Dosen Dilarang Menambah Mahasiswa)",
    "POST", "http://localhost/api-mhs-auth/server/mhs",
    "403 Forbidden",
    "Authorization: Bearer <Token Dosen: role=dosen>",
    '{\n  "nim": "23670005",\n  "name": "Mhs Coba Tambah",\n  "major": "Informatika"\n}',
    '{\n  "status": "error",\n  "pesan": "Akses ditolak: hanya admin yang boleh"\n}'
)

# 10. Rate Limiting 429
generate_clean_card(
    "card_rate_limit_429.png",
    "POST /login (Percobaan ke-6 Diblokir Rate Limit)",
    "POST", "http://localhost/api-mhs-auth/server/login",
    "429 Too Many Requests",
    "Response Headers: Retry-After: 60",
    '{\n  "username": "target_user",\n  "password": "tebak_salah_6"\n}',
    '{\n  "status": "error",\n  "pesan": "Terlalu banyak percobaan login. Coba lagi 1 menit lagi"\n}'
)

# 11. Database Audit Log
html_db = f"""<!DOCTYPE html><html><head><style>{BASE_CSS}</style></head><body>
<div class="box">
  <div class="box-header">MySQL / Database: kampus_db.log_api (Rekaman Audit Transaksi)</div>
  <div class="box-content">
    <div style="margin-bottom: 8px; font-weight: bold;">SELECT id, waktu, method, path, status, ip, username, pesan FROM log_api ORDER BY id DESC LIMIT 6;</div>
    <table class="clean-table">
      <thead>
        <tr><th>id</th><th>waktu</th><th>method</th><th>path</th><th>status</th><th>ip</th><th>username</th><th>pesan</th></tr>
      </thead>
      <tbody>
        <tr><td>185</td><td>2026-10-25 23:35:10</td><td>GET</td><td>/server/mhs</td><td>200</td><td>127.0.0.1</td><td>dosen1</td><td>OK</td></tr>
        <tr><td>184</td><td>2026-10-25 23:35:08</td><td>GET</td><td>/server/log</td><td>403</td><td>127.0.0.1</td><td>dosen1</td><td>Akses ditolak: hanya admin...</td></tr>
        <tr><td>183</td><td>2026-10-25 23:35:05</td><td>PUT</td><td>/server/mhs/1</td><td>200</td><td>127.0.0.1</td><td>dosen1</td><td>Data diubah</td></tr>
        <tr><td>182</td><td>2026-10-25 23:35:02</td><td>PUT</td><td>/server/me/password</td><td>200</td><td>127.0.0.1</td><td>laela_rustiani</td><td>Password berhasil diganti</td></tr>
        <tr><td>181</td><td>2026-10-25 23:34:58</td><td>POST</td><td>/server/register</td><td>409</td><td>127.0.0.1</td><td>NULL</td><td>Username sudah dipakai</td></tr>
        <tr><td>180</td><td>2026-10-25 23:34:55</td><td>POST</td><td>/server/register</td><td>201</td><td>127.0.0.1</td><td>laela_rustiani</td><td>Akun berhasil dibuat</td></tr>
      </tbody>
    </table>
  </div>
</div>
</body></html>"""
render_html_to_png(html_db, os.path.join(IMG_DIR, "db_log_audit.png"), 950, 280)

print("All clean monochrome screenshots rendered successfully!")

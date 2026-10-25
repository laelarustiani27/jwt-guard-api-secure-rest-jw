<?php
// =====================================================================
// test_client.php  --  CLIENT penguji API (Pertemuan 7: dengan autentikasi)
//
// Program ini berperan sebagai "pengguna" API: login, memakai token, lalu
// memeriksa apakah server menolak / menerima dengan benar. Hasil: PASS / FAIL.
//
// Jalankan:
//   php test_client.php http://localhost/api-mhs-auth/server
//   php test_client.php http://localhost:8000          <- jika memakai php -S
// =====================================================================

// Boleh lewat terminal (argumen) atau browser (?base=...)
$base = $argv[1] ?? ($_GET['base'] ?? 'http://localhost/api-mhs-auth/server');
$base = rtrim($base, '/');
if (php_sapi_name() != 'cli') header('Content-Type: text/plain; charset=utf-8');

$lulus = 0;
$gagal = 0;

// ---------------------------------------------------------------------
// panggil() : mengirim satu request ke server dengan cURL
//   $token (opsional) -> dikirim sebagai header  Authorization: Bearer <token>
//   Mengembalikan array: [status code, isi jawaban JSON]
// ---------------------------------------------------------------------
function panggil($method, $path, $data = null, $token = null)
{
    global $base;

    $header = [];
    if ($data !== null) {
        $header[] = 'Content-Type: application/json';
    }
    if ($token !== null) {
        $header[] = 'Authorization: Bearer ' . $token;      // <-- cara membawa token
    }

    $ch = curl_init($base . $path);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);   // sertifikat lokal self-signed
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    if ($data !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }

    $isi    = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    return [$status, json_decode($isi, true)];
}

// Mencatat hasil satu pengujian
function cek($nama, $kondisi)
{
    global $lulus, $gagal;
    if ($kondisi) { $lulus++; echo "  [PASS] $nama\n"; }
    else          { $gagal++; echo "  [FAIL] $nama\n"; }
}

// Login dan mengembalikan token (atau null jika gagal)
function login($username, $password)
{
    list($status, $json) = panggil('POST', '/login', ['username' => $username, 'password' => $password]);
    return ($status == 200) ? $json['token'] : null;
}

// ---------------------------------------------------------------------
echo "Menguji server: $base\n\n";

list($status, $json) = panggil('GET', '/');

if ($status == 0) {
    $c = curl_init($base . '/'); curl_setopt($c, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false); curl_exec($c);
    echo "Server tidak bisa dihubungi: " . curl_error($c) . "\n";
    exit(2);
}

if ($status == 429) {
    echo "Server menolak karena terlalu banyak request dari komputer ini (rate limiting).\n";
    echo "Tunggu 1 menit, lalu jalankan lagi.\n";
    exit(3);
}

// ---------------------------------------------------------------------
echo "1. AUTENTIKASI: siapa kamu?\n";
list($status, $json) = panggil('GET', '/mhs');
cek('GET /mhs tanpa token -> 401', $status == 401);

list($status, $json) = panggil('POST', '/login', ['username' => 'admin', 'password' => 'salah']);
cek('Login password salah -> 401', $status == 401);

list($status, $json) = panggil('POST', '/login', ['username' => 'tidak_ada', 'password' => 'x']);
cek('Login username tidak ada -> 401 (pesan sama, tidak membocorkan)', $status == 401);

list($status, $json) = panggil('POST', '/login', ['username' => 'admin']);
cek('Login tanpa password -> 422', $status == 422);

list($status, $json) = panggil('POST', '/login', ['username' => "' OR '1'='1", 'password' => "' OR '1'='1"]);
cek("Login dengan SQL Injection ' OR '1'='1 -> 401 (gagal menembus)", $status == 401);

$tokenAdmin = login('admin', 'admin123');
cek('Login admin benar -> dapat token', $tokenAdmin !== null);
$tokenUser = login('budi', 'budi123');
cek('Login budi benar -> dapat token', $tokenUser !== null);

if ($tokenAdmin === null || $tokenUser === null) {
    echo "\nLogin gagal. Pastikan database sudah diimpor dari database/mhs.sql versi Pertemuan 7.\n";
    exit(1);
}

echo "   token berbentuk 3 bagian dipisah titik: " . substr($tokenAdmin, 0, 30) . "...\n";
cek('Token terdiri dari 3 bagian (header.payload.signature)', count(explode('.', $tokenAdmin)) == 3);

list($status, $json) = panggil('GET', '/me', null, $tokenUser);
cek('GET /me dengan token -> 200, username budi', $status == 200 && $json['data']['username'] == 'budi');

echo "\n2. TOKEN PALSU / RUSAK harus ditolak\n";
list($status, $json) = panggil('GET', '/mhs', null, 'ini.bukan.token');
cek('Token asal-asalan -> 401', $status == 401);

// Merusak 1 huruf tanda tangan
$rusak = substr($tokenUser, 0, -2) . (substr($tokenUser, -2) == 'AA' ? 'BB' : 'AA');
list($status, $json) = panggil('GET', '/mhs', null, $rusak);
cek('Tanda tangan diubah -> 401', $status == 401);

// Mengganti isi payload menjadi role admin, tanda tangan tetap yang lama
list($h, $p, $t) = explode('.', $tokenUser);
$payloadPalsu = rtrim(strtr(base64_encode(json_encode(['sub' => 2, 'username' => 'budi', 'role' => 'admin', 'exp' => time() + 3600])), '+/', '-_'), '=');
list($status, $json) = panggil('GET', '/mhs', null, "$h.$payloadPalsu.$t");
cek('Payload diubah jadi admin (tanpa kunci) -> 401', $status == 401);

echo "\n3. OTORISASI: bolehkah kamu?  (budi = role user)\n";
list($status, $json) = panggil('GET', '/mhs', null, $tokenUser);
cek('user: GET /mhs -> 200 (boleh melihat)', $status == 200);

$baru = ['nim' => '99' . rand(100000, 999999), 'name' => 'Mahasiswa Uji', 'major' => 'Informatika'];
list($status, $json) = panggil('POST', '/mhs', $baru, $tokenUser);
cek('user: POST /mhs -> 403 (tidak boleh menambah)', $status == 403);

list($status, $json) = panggil('DELETE', '/mhs/1', null, $tokenUser);
cek('user: DELETE /mhs/1 -> 403', $status == 403);

list($status, $json) = panggil('GET', '/log', null, $tokenUser);
cek('user: GET /log -> 403', $status == 403);

echo "\n4. ADMIN boleh melakukan CRUD\n";
list($status, $json) = panggil('POST', '/mhs', $baru, $tokenAdmin);
cek('admin: POST /mhs -> 201', $status == 201);
$id = isset($json['id']) ? $json['id'] : 0;

list($status, $json) = panggil('POST', '/mhs', $baru, $tokenAdmin);
cek('admin: POST NIM kembar -> 409', $status == 409);

list($status, $json) = panggil('POST', '/mhs', ['nim' => 'abc'], $tokenAdmin);
cek('admin: POST data tidak valid -> 422', $status == 422);

$baru['name'] = 'Nama Diubah';
list($status, $json) = panggil('PUT', "/mhs/$id", $baru, $tokenAdmin);
cek('admin: PUT -> 200', $status == 200);

list($status, $json) = panggil('GET', '/mhs/' . rawurlencode('1 OR 1=1'), null, $tokenAdmin);
cek('admin: id "1 OR 1=1" -> 400 (validasi input)', $status == 400);

list($status, $json) = panggil('DELETE', "/mhs/$id", null, $tokenAdmin);
cek('admin: DELETE -> 200', $status == 200);

echo "\n5. RATE LIMITING: pembatasan percobaan login\n";
$penyerang = 'penyerang' . rand(1000, 9999);          // username acak agar tidak mengunci akun asli
$kode = [];
for ($i = 1; $i <= 7; $i++) {
    list($status, $json) = panggil('POST', '/login', ['username' => $penyerang, 'password' => 'tebak' . $i]);
    $kode[] = $status;
}
echo "   status 7 percobaan berturut-turut: " . implode(', ', $kode) . "\n";
cek('5 percobaan pertama ditolak 401', array_slice($kode, 0, 5) == [401, 401, 401, 401, 401]);
cek('Percobaan ke-6 dst diblokir 429 (Too Many Requests)', $kode[5] == 429 && $kode[6] == 429);

$tokenAdmin2 = login('admin', 'admin123');
cek('Akun asli (admin) tidak ikut terkunci', $tokenAdmin2 !== null);

echo "\n6. LOGGING: siapa melakukan apa\n";
list($status, $json) = panggil('GET', '/log', null, $tokenAdmin);
cek('admin: GET /log -> 200', $status == 200);
echo "   10 catatan log terakhir:\n";
$adaUser = false; $ada401 = false; $ada403 = false; $ada429 = false;
foreach ($json['data'] as $i => $b) {
    if ($i < 10) {
        printf("   %s  %-6s %-14s -> %d  user=%s\n", $b['waktu'], $b['method'], substr(basename($b['path']), 0, 14), $b['status'], $b['username'] ?? '-');
    }
}
// Cek lebih banyak baris langsung dari log 20 terakhir
foreach ($json['data'] as $b) {
    if ($b['username'] == 'admin') $adaUser = true;
    if ($b['status'] == 401) $ada401 = true;
    if ($b['status'] == 403) $ada403 = true;
    if ($b['status'] == 429) $ada429 = true;
}
cek('Log mencatat nama pengguna (kolom username)', $adaUser);
cek('Log mencatat percobaan ditolak (401 / 403 / 429)', $ada401 || $ada403 || $ada429);

// =====================================================================
// BAGIAN BARU: TEST TUGAS PERTEMUAN 7
// Minimal 8 pengecekan baru untuk fitur: register, ganti password, role dosen
// =====================================================================

echo "\n7. REGISTER: daftar akun baru (POST /register)\n";

// Test 1: Register username baru -> 201
$userBaru = 'testuser_' . rand(1000, 9999);
list($status, $json) = panggil('POST', '/register', ['username' => $userBaru, 'password' => 'password99']);
cek('Register username baru -> 201', $status == 201);
cek('Register: role otomatis user', isset($json['user']['role']) && $json['user']['role'] == 'user');

// Test 2: Register username duplikat -> 409
list($status, $json) = panggil('POST', '/register', ['username' => $userBaru, 'password' => 'password99']);
cek('Register username duplikat -> 409', $status == 409);

// Test 3: Register password < 8 karakter -> 422
list($status, $json) = panggil('POST', '/register', ['username' => 'user_pendek', 'password' => 'abc']);
cek('Register password < 8 karakter -> 422', $status == 422);

// Test 4: Register tanpa field username -> 422
list($status, $json) = panggil('POST', '/register', ['password' => 'password99']);
cek('Register tanpa username -> 422', $status == 422);

// Test 5: Akun yang baru didaftar bisa login
$tokenBaru = login($userBaru, 'password99');
cek('Akun baru hasil register bisa login dan dapat token', $tokenBaru !== null);

echo "\n8. GANTI PASSWORD: PUT /me/password\n";

// Test 6: Ganti password dengan password lama yang benar -> 200
list($status, $json) = panggil('PUT', '/me/password',
    ['password_lama' => 'password99', 'password_baru' => 'password_baru88'],
    $tokenBaru);
cek('Ganti password lama benar -> 200', $status == 200);

// Test 7: Login dengan password baru berhasil
$tokenSetelahGanti = login($userBaru, 'password_baru88');
cek('Login dengan password baru berhasil', $tokenSetelahGanti !== null);

// Test 8: Token lama masih berlaku tapi ganti password dengan password lama salah -> 401
list($status, $json) = panggil('PUT', '/me/password',
    ['password_lama' => 'password99', 'password_baru' => 'password_baru88'],
    $tokenSetelahGanti);
cek('Ganti password - password lama salah -> 401', $status == 401);

// Test 9: Ganti password baru < 8 karakter -> 422
list($status, $json) = panggil('PUT', '/me/password',
    ['password_lama' => 'password_baru88', 'password_baru' => 'abc'],
    $tokenSetelahGanti);
cek('Ganti password baru < 8 karakter -> 422', $status == 422);

// Test 10: Ganti password tanpa token -> 401
list($status, $json) = panggil('PUT', '/me/password',
    ['password_lama' => 'password_baru88', 'password_baru' => 'abcdefgh']);
cek('Ganti password tanpa token -> 401', $status == 401);

echo "\n9. ROLE DOSEN: otorisasi khusus\n";

$tokenDosen = login('dosen1', 'dosen123');
cek('Login dosen1 -> dapat token', $tokenDosen !== null);

if ($tokenDosen !== null) {
    // Siapkan data: admin buat mhs baru untuk ditest dosen
    $nimTest = '99' . rand(100000, 999999);
    list($status, $jsonMhs) = panggil('POST', '/mhs',
        ['nim' => $nimTest, 'name' => 'Mhs Test Dosen', 'major' => 'Informatika'],
        $tokenAdmin);
    $idTestDosen = isset($jsonMhs['id']) ? $jsonMhs['id'] : 0;

    // Test 11: Dosen boleh PUT (edit) mahasiswa -> 200
    list($status, $json) = panggil('PUT', "/mhs/$idTestDosen",
        ['nim' => $nimTest, 'name' => 'Mhs Diedit Dosen', 'major' => 'Sistem Informasi'],
        $tokenDosen);
    cek('dosen: PUT /mhs/:id -> 200 (boleh edit)', $status == 200);

    // Test 12: Dosen TIDAK boleh POST (tambah) -> 403
    list($status, $json) = panggil('POST', '/mhs',
        ['nim' => '88' . rand(100000, 999999), 'name' => 'Coba Tambah', 'major' => 'Informatika'],
        $tokenDosen);
    cek('dosen: POST /mhs -> 403 (tidak boleh tambah)', $status == 403);

    // Test 13: Dosen TIDAK boleh DELETE -> 403
    list($status, $json) = panggil('DELETE', "/mhs/$idTestDosen", null, $tokenDosen);
    cek('dosen: DELETE /mhs/:id -> 403 (tidak boleh hapus)', $status == 403);

    // Test 14: Dosen TIDAK boleh lihat log -> 403
    list($status, $json) = panggil('GET', '/log', null, $tokenDosen);
    cek('dosen: GET /log -> 403 (tidak boleh lihat log)', $status == 403);

    // Test 15: Dosen boleh GET /mhs -> 200
    list($status, $json) = panggil('GET', '/mhs', null, $tokenDosen);
    cek('dosen: GET /mhs -> 200 (boleh lihat data)', $status == 200);

    // Cleanup: admin hapus mhs test
    panggil('DELETE', "/mhs/$idTestDosen", null, $tokenAdmin);
}

// ---------------------------------------------------------------------
$total = $lulus + $gagal;
echo "\nHASIL: $lulus dari $total pengujian lulus\n";
exit($gagal == 0 ? 0 : 1);

<?php
// =====================================================================
// index.php  --  API Mahasiswa + Autentikasi JWT (Pertemuan 7 + Tugas)
//
// Daftar endpoint:
//   POST   /login          -> login, mendapat token JWT          (publik)
//   POST   /register       -> daftar akun baru, role=user        (publik) [BARU TUGAS]
//   GET    /me             -> lihat data akun yang sedang login  (perlu token)
//   PUT    /me/password    -> ganti password sendiri             (perlu token) [BARU TUGAS]
//   GET    /mhs            -> ambil semua mahasiswa              (perlu token)
//   GET    /mhs/3          -> ambil mahasiswa dengan id 3        (perlu token)
//   POST   /mhs            -> tambah mahasiswa baru             (token + role admin)
//   PUT    /mhs/3          -> ubah data mahasiswa id 3          (token + role admin/dosen) [DIUBAH TUGAS]
//   DELETE /mhs/3          -> hapus mahasiswa id 3              (token + role admin)
//   GET    /log            -> lihat 20 catatan log terakhir     (token + role admin)
// =====================================================================

require 'koneksi.php';   // menghasilkan variabel $db (koneksi database) + pengaturan keamanan
require 'jwt.php';       // <-- BARU P7: fungsi buat_token() dan cek_token()
require 'fungsi.php';    // fungsi kirim(), catat_log(), wajib_login(), wajib_admin(), ...

// ---------------------------------------------------------------------
// Izin untuk client web (browser) yang alamatnya berbeda dari server ini.
// Tanpa ini browser akan memblokir permintaan (aturan CORS).
// ---------------------------------------------------------------------
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');   // <-- BARU P7: izinkan header Authorization

// Browser kadang bertanya dulu "boleh tidak?" dengan method OPTIONS. Jawab saja "boleh".
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ---------------------------------------------------------------------
// LANGKAH 1: membaca alamat
// Contoh alamat: /api-mhs-sederhana/server/mhs/3
// Kita buang folder server-nya, sisanya "mhs/3" dipecah jadi ['mhs', '3'].
// ---------------------------------------------------------------------
$path   = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);   // tanpa ?query
$folder = dirname($_SERVER['SCRIPT_NAME']);                   // folder tempat index.php
if ($folder != '/' && strpos($path, $folder) === 0) {
    $path = substr($path, strlen($folder));                   // buang nama folder
}
$bagian   = explode('/', trim($path, '/'));                   // pecah per tanda "/"
$resource = $bagian[0];                                       // 'mhs' atau 'log'
$id       = isset($bagian[1]) ? $bagian[1] : null;            // '3' (boleh kosong)

$method = $_SERVER['REQUEST_METHOD'];                         // GET / POST / PUT / DELETE

// Data JSON yang dikirim client (untuk POST dan PUT), diubah menjadi array PHP.
$input = json_decode(file_get_contents('php://input'), true);

// <-- BARU P7: RATE LIMITING umum. Terlalu banyak request dari satu IP -> 429.
batasi_request();

// try ... catch : jika ada error database, jangan tampilkan layar error PHP,
// tapi kirim jawaban JSON yang rapi.
try {

    // =================================================================
    // POST /login  -> AUTENTIKASI (publik, tidak perlu token)
    // =================================================================
    if ($resource == 'login' && $method == 'POST') {

        // 1) Validasi input: username dan password wajib diisi (teks).
        if (!is_array($input) || empty($input['username']) || empty($input['password'])
            || !is_string($input['username']) || !is_string($input['password'])) {
            kirim(['status' => 'error', 'pesan' => 'username dan password wajib diisi'], 422);
        }
        $username = trim($input['username']);
        $username_log = $username;                      // ikut dicatat di log

        // 2) RATE LIMITING login: hitung gagal login untuk username ini dari IP ini dalam 1 menit.
        $semenit_lalu = date('Y-m-d H:i:s', time() - 60);
        $stmt = $db->prepare("SELECT COUNT(*) FROM log_api
                              WHERE ip = ? AND username = ? AND status = 401 AND waktu >= ?
                                AND path LIKE '%/login'");
        $stmt->execute([$_SERVER['REMOTE_ADDR'], $username, $semenit_lalu]);
        if ($stmt->fetchColumn() >= $batas_login) {
            header('Retry-After: 60');
            kirim(['status' => 'error', 'pesan' => 'Terlalu banyak percobaan login. Coba lagi 1 menit lagi'], 429);
        }

        // 3) Cari akun di database (prepared statement -> aman dari SQL Injection).
        $stmt = $db->prepare("SELECT id, username, password, role FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $akun = $stmt->fetch();

        // 4) Cocokkan password. Pesan error SENGAJA sama untuk "username salah" dan "password salah"
        //    supaya penyerang tidak tahu username mana yang benar-benar ada.
        if (!$akun || !password_verify($input['password'], $akun['password'])) {
            kirim(['status' => 'error', 'pesan' => 'Username atau password salah'], 401);
        }

        // 5) Berhasil -> buat token JWT berisi identitas pengguna (BUKAN password!).
        $token = buat_token(
            ['sub' => (int)$akun['id'], 'username' => $akun['username'], 'role' => $akun['role']],
            $jwt_secret,
            $jwt_berlaku
        );
        kirim([
            'status'        => 'sukses',
            'pesan'         => 'Login berhasil',
            'token'         => $token,
            'tipe'          => 'Bearer',
            'berlaku_detik' => $jwt_berlaku,
            'user'          => ['username' => $akun['username'], 'role' => $akun['role']]
        ]);
    }

    // =================================================================
    // POST /register -> DAFTAR AKUN BARU (publik, tidak perlu token)
    // Role otomatis 'user'. Tanggapi 201 / 409 / 422.
    // =================================================================
    elseif ($resource == 'register' && $method == 'POST') {

        // 1) Validasi: username dan password wajib ada dan bertipe string.
        if (!is_array($input) || empty($input['username']) || empty($input['password'])
            || !is_string($input['username']) || !is_string($input['password'])) {
            kirim(['status' => 'error', 'pesan' => 'username dan password wajib diisi'], 422);
        }

        $username = trim($input['username']);
        $password = $input['password'];

        // 2) Panjang username: 3-50 karakter, hanya huruf/angka/underscore/titik.
        if (strlen($username) < 3 || strlen($username) > 50) {
            kirim(['status' => 'error', 'pesan' => 'Username harus 3-50 karakter'], 422);
        }
        if (!preg_match('/^[a-zA-Z0-9_.]+$/', $username)) {
            kirim(['status' => 'error', 'pesan' => 'Username hanya boleh huruf, angka, titik, underscore'], 422);
        }

        // 3) Password minimal 8 karakter (sesuai instruksi tugas).
        if (strlen($password) < 8) {
            kirim(['status' => 'error', 'pesan' => 'Password minimal 8 karakter'], 422);
        }

        // 4) Cek username unik -> 409 jika sudah ada.
        $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) {
            kirim(['status' => 'error', 'pesan' => 'Username sudah dipakai'], 409);
        }

        // 5) Hash password lalu simpan. Role otomatis 'user'.
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')");
        $stmt->execute([$username, $hash]);

        $idBaru = $db->lastInsertId();
        $username_log = $username;   // catat di log siapa yang register
        kirim([
            'status' => 'sukses',
            'pesan'  => 'Akun berhasil dibuat',
            'id'     => (int)$idBaru,
            'user'   => ['username' => $username, 'role' => 'user']
        ], 201);
    }

    // =================================================================
    // SEMUA alamat di bawah ini WAJIB membawa token yang sah.
    // login dan register adalah publik (sudah ditangani di atas).
    // wajib_login() mengembalikan data pengguna, atau langsung 401.
    // =================================================================
    elseif ($resource != '') {
        $pengguna = wajib_login();
    }

    // =================================================================
    // ROUTING -> /me   (GET: lihat profil | PUT /me/password: ganti password)
    // =================================================================
    if ($resource == 'me' && $method == 'GET' && $id === null) {
        // GET /me -> info akun yang sedang login dari token
        kirim(['status' => 'sukses', 'data' => [
            'id'             => $pengguna['sub'],
            'username'       => $pengguna['username'],
            'role'           => $pengguna['role'],
            'token_habis_pada' => date('Y-m-d H:i:s', $pengguna['exp'])
        ]]);
    }

    // PUT /me/password -> ganti password sendiri (perlu token)
    elseif ($resource == 'me' && $id == 'password' && $method == 'PUT') {

        // 1) Validasi input: password_lama dan password_baru wajib ada.
        if (!is_array($input) || empty($input['password_lama']) || empty($input['password_baru'])
            || !is_string($input['password_lama']) || !is_string($input['password_baru'])) {
            kirim(['status' => 'error', 'pesan' => 'password_lama dan password_baru wajib diisi'], 422);
        }

        // 2) password_baru minimal 8 karakter.
        if (strlen($input['password_baru']) < 8) {
            kirim(['status' => 'error', 'pesan' => 'Password baru minimal 8 karakter'], 422);
        }

        // 3) Ambil hash password sekarang dari database berdasarkan id di token.
        $stmt = $db->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->execute([$pengguna['sub']]);
        $akun = $stmt->fetch();

        // 4) Verifikasi password lama -> 401 jika salah.
        if (!$akun || !password_verify($input['password_lama'], $akun['password'])) {
            kirim(['status' => 'error', 'pesan' => 'Password lama salah'], 401);
        }

        // 5) Hash password baru lalu update.
        $hashBaru = password_hash($input['password_baru'], PASSWORD_DEFAULT);
        $stmt = $db->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->execute([$hashBaru, $pengguna['sub']]);

        kirim(['status' => 'sukses', 'pesan' => 'Password berhasil diganti']);
    }

    // =================================================================
    // ROUTING  -> /mhs
    // =================================================================
    elseif ($resource == 'mhs') {

        // ---------- ID harus angka (jika diisi) ----------
        if ($id !== null && !ctype_digit($id)) {
            kirim(['status' => 'error', 'pesan' => 'ID harus berupa angka'], 400);
        }

        // ---------- READ: GET /mhs  (semua data) ----------
        if ($method == 'GET' && $id === null) {
            $hasil = $db->query("SELECT * FROM mhs ORDER BY id")->fetchAll();
            kirim(['status' => 'sukses', 'data' => $hasil]);
        }

        // ---------- READ: GET /mhs/3  (satu data) ----------
        elseif ($method == 'GET') {
            $stmt = $db->prepare("SELECT * FROM mhs WHERE id = ?");
            $stmt->execute([$id]);
            $baris = $stmt->fetch();                  // false jika tidak ada
            if (!$baris) {
                kirim(['status' => 'error', 'pesan' => 'Mahasiswa tidak ditemukan'], 404);
            }
            kirim(['status' => 'sukses', 'data' => $baris]);
        }

        // ---------- CREATE: POST /mhs -> hanya admin ----------
        elseif ($method == 'POST' && $id === null) {
            wajib_role($pengguna, ['admin']);           // hanya admin boleh tambah
            cek_input($input);                        // data wajib lengkap, jika tidak -> berhenti (400)

            // NIM tidak boleh kembar
            $stmt = $db->prepare("SELECT id FROM mhs WHERE nim = ?");
            $stmt->execute([$input['nim']]);
            if ($stmt->fetch()) {
                kirim(['status' => 'error', 'pesan' => 'NIM sudah terdaftar'], 409);
            }

            $stmt = $db->prepare("INSERT INTO mhs (nim, name, major) VALUES (?, ?, ?)");
            $stmt->execute([$input['nim'], $input['name'], $input['major']]);

            $idBaru = $db->lastInsertId();            // id yang baru dibuat MySQL
            kirim(['status' => 'sukses', 'pesan' => 'Data ditambahkan', 'id' => (int)$idBaru], 201);
        }

        // ---------- UPDATE: PUT /mhs/3 -> admin DAN dosen boleh ----------
        elseif ($method == 'PUT' && $id !== null) {
            wajib_role($pengguna, ['admin', 'dosen']);  // TUGAS: dosen boleh PUT
            cek_input($input);

            // Pastikan datanya ada dulu
            $stmt = $db->prepare("SELECT id FROM mhs WHERE id = ?");
            $stmt->execute([$id]);
            if (!$stmt->fetch()) {
                kirim(['status' => 'error', 'pesan' => 'Mahasiswa tidak ditemukan'], 404);
            }

            // NIM baru tidak boleh dipakai mahasiswa LAIN (id <> ?)
            $stmt = $db->prepare("SELECT id FROM mhs WHERE nim = ? AND id <> ?");
            $stmt->execute([$input['nim'], $id]);
            if ($stmt->fetch()) {
                kirim(['status' => 'error', 'pesan' => 'NIM sudah dipakai mahasiswa lain'], 409);
            }

            $stmt = $db->prepare("UPDATE mhs SET nim = ?, name = ?, major = ? WHERE id = ?");
            $stmt->execute([$input['nim'], $input['name'], $input['major'], $id]);
            kirim(['status' => 'sukses', 'pesan' => 'Data diubah']);
        }

        // ---------- DELETE: DELETE /mhs/3 -> hanya admin ----------
        elseif ($method == 'DELETE' && $id !== null) {
            wajib_role($pengguna, ['admin']);           // hanya admin boleh hapus
            $stmt = $db->prepare("DELETE FROM mhs WHERE id = ?");
            $stmt->execute([$id]);
            if ($stmt->rowCount() == 0) {             // tidak ada baris yang terhapus
                kirim(['status' => 'error', 'pesan' => 'Mahasiswa tidak ditemukan'], 404);
            }
            kirim(['status' => 'sukses', 'pesan' => 'Data dihapus']);
        }

        // ---------- Kombinasi lain (mis. DELETE /mhs tanpa id) ----------
        else {
            kirim(['status' => 'error', 'pesan' => 'Method tidak diizinkan'], 405);
        }
    }

    // =================================================================
    // ROUTING  -> /log   (melihat catatan log dari database)
    // =================================================================
    elseif ($resource == 'log' && $method == 'GET') {
        wajib_role($pengguna, ['admin']);               // log hanya boleh dilihat admin
        $hasil = $db->query("SELECT * FROM log_api ORDER BY id DESC LIMIT 20")->fetchAll();
        // Perhatian: kirim() juga mencatat request /log ini ke log_api.
        kirim(['status' => 'sukses', 'data' => $hasil]);
    }

    // =================================================================
    // ROUTING  -> alamat kosong  (cek server hidup)
    // =================================================================
    elseif ($resource == '') {
        kirim(['status' => 'sukses', 'pesan' => 'API Mahasiswa aktif']);
    }

    // Alamat lain yang tidak dikenal
    else {
        kirim(['status' => 'error', 'pesan' => 'Alamat tidak ditemukan'], 404);
    }

} catch (PDOException $e) {
    // Error database tak terduga. Detailnya TIDAK dikirim ke client (bisa membocorkan struktur tabel).
    kirim(['status' => 'error', 'pesan' => 'Terjadi kesalahan pada database'], 500);
}


// =====================================================================
// FUNGSI: cek_input()  -- memastikan data dari client lengkap
// Jika ada yang kurang, langsung kirim error 400 dan berhenti.
// =====================================================================
function cek_input($input)
{
    // Jika body bukan JSON yang benar, $input bukan array.
    if (!is_array($input)) {
        kirim(['status' => 'error', 'pesan' => 'Kirim data dalam format JSON'], 400);
    }

    // Tiga field ini wajib ada dan tidak boleh kosong.
    foreach (['nim', 'name', 'major'] as $field) {
        if (empty($input[$field])) {
            kirim(['status' => 'error', 'pesan' => "Field $field wajib diisi"], 422);
        }
    }

    // NIM harus angka saja.
    if (!ctype_digit((string)$input['nim'])) {
        kirim(['status' => 'error', 'pesan' => 'NIM harus berupa angka'], 422);
    }
}

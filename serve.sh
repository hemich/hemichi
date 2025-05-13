#!/bin/bash

# Path lengkap ke script PHP Anda
PHP_SCRIPT="/home/dsuni6ersity2c/public_html/server.php"

# Nama proses parent yang konsisten
PROCESS_NAME="server_dsuniversity_process"

# Fungsi untuk menjalankan script PHP
start_php_script() {
    php "$PHP_SCRIPT" &
    echo "Memulai script PHP: $PHP_SCRIPT dengan PID $!"
}

# Jalankan script PHP pertama kali
start_php_script

# Loop pengawasan
while true; do
    # Cek apakah process parent masih berjalan
    if ! pgrep -f "$PROCESS_NAME" > /dev/null; then
        echo "$(date): Process $PROCESS_NAME tidak berjalan. Restart dalam 10 detik..."
        sleep 10
        start_php_script
    fi
    # Tunggu sebelum pengecekan berikutnya
    sleep 5
done

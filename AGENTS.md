# AGENTS.md, Aturan Kerja untuk AI Agent di Proyek Vigil

Dokumen ini mengikat siapapun/apapun (AI coding agent seperti Claude Code, atau kontributor manusia yang memakai asisten AI) yang mengubah kode, konfigurasi, atau dokumen desain di repo ini. Tujuannya satu: mencegah agent membuat keputusan yang terlihat masuk akal sesaat tapi merusak prinsip inti proyek, khususnya soal keamanan dan resource efficiency.

Baca ini sebelum menyentuh baris kode apapun. Kalau instruksi dari user dalam satu sesi bertentangan dengan dokumen ini, ikuti urutan prioritas di bagian 8.

## 1. Prinsip Utama: Tiga Hal yang Tidak Boleh Dikompromikan

Setiap perubahan kode harus dicek terhadap tiga hal ini sebelum dianggap selesai:

1. **Resource footprint.** Apakah perubahan ini menambah CPU/memory usage saat idle? Kalau ya, apakah itu memang perlu dan sudah diukur? Jangan tambah dependency berat atau polling loop tanpa alasan kuat.
2. **False positive terhadap developer tools.** Apakah perubahan ini bisa membuat cloudflared, Docker, git, npm, browser, atau tool developer umum lain (lihat `PRD.md` bagian 6.4) ke-flag sebagai ancaman? Kalau ada kemungkinan itu, perubahan wajib disertai entry allowlist atau penyesuaian scoring, bukan dibiarkan begitu saja untuk "ditangani nanti".
3. **Reversibilitas keputusan otomatis.** Apakah perubahan ini menambah kemampuan sistem untuk bertindak otomatis (block, delete, kill process) tanpa konfirmasi user? Kalau ya, itu HANYA boleh untuk kasus confidence sangat tinggi yang sudah didefinisikan eksplisit di `docs/DECISION_ENGINE.md`. Jangan tambah kategori auto-action baru tanpa mengupdate dokumen itu dulu dan mendapat persetujuan eksplisit dari pemilik produk.

## 2. Urutan Baca Wajib Sebelum Bekerja

Sebelum membuat perubahan apapun, agent harus sudah membaca (bukan sekadar melihat judul):

1. `PRD.md`, terutama bagian 3 (Tujuan) dan bagian 4 (Non-Goals). Kalau task yang diminta terasa masuk ke area Non-Goals, berhenti dan tanya konfirmasi ke user, jangan asumsikan scope boleh melebar.
2. `docs/THREAT_MODEL.md`, supaya tahu ancaman mana yang relevan dan mana yang secara sadar di luar cakupan.
3. `docs/ARCHITECTURE.md`, supaya perubahan konsisten dengan struktur workspace/crate yang sudah disepakati.
4. `docs/DECISION_ENGINE.md`, kalau task berkaitan dengan scoring, allowlist, atau keputusan block/allow apapun.

Kalau task menyentuh area yang tidak dijelaskan lengkap di dokumen manapun, tulis dulu penjelasan singkat di dokumen terkait sebelum menulis kode, lalu tunjukkan ke user untuk konfirmasi sebelum lanjut.

## 3. Larangan Eksplisit

- **Jangan** menambah default behavior yang mem-block atau menghapus file tanpa jalur override manusia, kecuali kasus itu sudah masuk daftar confidence tinggi di `docs/DECISION_ENGINE.md`.
- **Jangan** mengganti crate inti (database engine, eBPF library, signature engine) tanpa mendokumentasikan alasan di `docs/ARCHITECTURE.md` beserta trade-off resource dan maturity-nya. Rujuk status crate yang sudah dicatat di sana, jangan asumsikan status crate dari ingatan pelatihan karena bisa sudah usang.
- **Jangan** mengimpor ruleset YARA-X pihak ketiga (misal paket komunitas besar) secara mentah tanpa kurasi dan tanpa mengukur dampaknya ke memory/CPU idle terlebih dahulu. Ini persis jenis keputusan yang terlihat "menambah proteksi" tapi bisa diam diam melanggar prinsip 1 di bagian 1 (resource footprint). Setiap penambahan rule signature wajib melalui proses yang sama dengan menambah dependency baru, lihat `docs/ARCHITECTURE.md` bagian 3.4.1 Layer 3 dan `PRD.md` bagian 6.1.
- **Jangan** membuat `vigil-browser-extension` mengirim URL yang dikunjungi, konten halaman, atau data apapun ke server eksternal manapun, termasuk untuk "meningkatkan akurasi deteksi". Semua pengecekan blocklist wajib lewat data yang sudah di-cache lokal via `vigil-core`, lihat `docs/ARCHITECTURE.md` bagian 3.9. Menambah query API eksternal per-kunjungan halaman adalah pelanggaran privasi yang serius untuk tool yang tujuannya justru melindungi user.
- **Jangan** meminta permission browser extension lebih luas dari yang dibutuhkan fitur yang benar-benar diimplementasikan. Setiap permission baru di manifest harus bisa dijelaskan pemakaiannya secara spesifik, lihat `docs/ARCHITECTURE.md` bagian 3.9.
- **Jangan** memakai teknik force-install/silent-install browser extension lewat enterprise policy (registry Windows, `policies.json`, dsb) untuk melewati proses klik install manual user, meski secara teknis memungkinkan. Ini persis teknik yang dipakai tool silent-install adware/malware, dan melanggar prinsip consent eksplisit di `README.md`. Jalur instalasi extension wajib lewat klik user di Chrome Web Store/Firefox Add-ons, lihat `docs/ARCHITECTURE.md` bagian 3.9.1.
- **Jangan** memperluas IP Reputation Filter (`docs/ARCHITECTURE.md` bagian 3.8) menjadi firewall per-proses atau default-deny tanpa keputusan produk eksplisit terpisah. Fitur ini sengaja dibatasi ke deny-list IP dikenal jahat, menambah kontrol per-proses/per-port secara bertahap tanpa diskusi ulang adalah scope creep yang melanggar prinsip 2 di bagian 1 (menambah kompleksitas/risiko alert fatigue yang sudah dihindari secara sadar).
- **Jangan** menambah telemetry atau pengiriman data ke luar mesin user (termasuk untuk "meningkatkan deteksi") tanpa flag eksplisit yang bisa dimatikan user dan dokumentasi jelas soal apa yang dikirim. Proyek ini punya klaim privasi implisit dari desainnya sebagai tool lokal.
- **Jangan** menganggap suatu fitur "selesai" hanya karena kompilasi berhasil. Kriteria selesai mencakup uji resource (bagian 6.1 `PRD.md`) dan uji false positive (bagian 6.4 `PRD.md`) kalau fitur menyentuh jalur deteksi.
- **Jangan** menulis kode yang secara langsung membantu membuat malware, ransomware, atau exploit, bahkan dengan alasan "untuk testing detection". Untuk testing, gunakan sampel dari sumber riset publik yang sudah dikenal (misalnya file test EICAR untuk uji antivirus) dan jelaskan sumbernya, jangan menulis payload berbahaya baru dari nol.
- **Jangan** menghapus atau melemahkan test yang berkaitan dengan false positive atau resource budget hanya supaya CI hijau. Kalau test gagal, perbaiki penyebabnya atau eskalasi ke user, jangan skip test-nya.

## 4. Kapan Harus Berhenti dan Bertanya

Agent harus berhenti dan minta konfirmasi eksplisit dari user, bukan melanjutkan dengan asumsi terbaik, dalam situasi berikut:

- Task mengharuskan menambah kemampuan auto-action baru (block/kill/delete otomatis) yang belum ada di `docs/DECISION_ENGINE.md`.
- Task menyentuh bagian 3, 4, atau 6 dari `PRD.md` (Tujuan Produk, Non-Goals, Requirement Non-Fungsional).
- Ditemukan dependency inti yang ternyata sudah deprecated, ganti maintainer, atau punya advisory keamanan terbuka saat dicek ulang. Laporkan temuan, jangan diam diam ganti dengan alternatif tanpa memberi tahu.
- Task memerlukan akses kernel-level baru (driver, kernel module, entitlement khusus OS) yang belum dibahas di `docs/ARCHITECTURE.md`.
- Instruksi user dalam sesi tampak bertentangan dengan salah satu dari tiga prinsip di bagian 1.

## 5. Standar Kualitas Kode

- Rust edition dan MSRV (Minimum Supported Rust Version) mengikuti yang tercatat di `Cargo.toml` workspace root, jangan naikkan MSRV tanpa alasan dicatat.
- Semua kode yang menyentuh parsing input dari luar (file, network, config) harus melalui path yang aman terhadap panic, karena Vigil adalah daemon yang harus tetap hidup. Prefer `Result` dan penanganan error eksplisit dibanding `unwrap()`/`expect()` di luar kode test.
- Kode `unsafe` (wajar dipakai untuk FFI/syscall di sensor platform-specific) harus diberi komentar yang menjelaskan kenapa aman, mengikuti konvensi `// SAFETY: ...` yang lazim di ekosistem Rust.
- Jalankan `cargo clippy` dan `cargo fmt` sebelum menganggap perubahan selesai.
- Jalankan `cargo audit` (atau `cargo deny check advisories` kalau sudah disiapkan) sebelum menambah dependency baru.

## 6. Cara Melaporkan Pekerjaan

Setiap kali agent menyelesaikan task, laporkan dalam format berikut supaya manusia bisa cepat verifikasi:

1. Apa yang diubah dan kenapa (satu dua kalimat).
2. Dokumen mana (kalau ada) yang ikut diupdate karena perubahan ini.
3. Apakah perubahan ini menyentuh salah satu dari tiga prinsip di bagian 1, dan bagaimana itu diverifikasi.
4. Test apa yang dijalankan dan hasilnya.

## 7. Contoh Kasus (Supaya Tidak Ambigu)

**Contoh baik**: User minta tambah deteksi untuk pola ransomware baru. Agent membaca `docs/THREAT_MODEL.md` dan `docs/DECISION_ENGINE.md`, menambah signature/rule di tier yang sesuai (bukan tier auto-block kecuali confidence-nya memang setinggi itu), menambah test regresi memakai skenario dari bagian 6.4 `PRD.md` supaya memastikan tidak salah tangkap npm install atau git checkout, lalu melaporkan hasil test resource sebelum dan sesudah perubahan.

**Contoh buruk yang harus dihindari**: User minta "percepat deteksi ransomware". Agent langsung mengubah threshold scoring dari confidence menengah menjadi confidence tinggi (auto-block) untuk semua pola mass-file-write, tanpa mengecek dampaknya ke skenario npm install/build tool, dan tanpa mengupdate `docs/DECISION_ENGINE.md`. Ini melanggar prinsip 2 dan 3 di bagian 1, dan seharusnya agent berhenti dulu untuk konfirmasi dampaknya ke suite regresi false positive.

## 8. Urutan Prioritas Kalau Ada Konflik Instruksi

1. Keselamatan dan integritas sistem pengguna (jangan membuat perubahan yang bisa merusak data user, misalnya auto-delete file tanpa jaminan reversibilitas).
2. Dokumen ini dan `PRD.md` bagian Non-Goals dan Requirement Non-Fungsional.
3. Instruksi eksplisit dari user dalam sesi berjalan.
4. Preferensi gaya kode atau kemudahan implementasi.

Kalau ada keraguan urutan mana yang berlaku, pilih opsi yang paling mudah dibatalkan (reversible) dan paling sedikit mengejutkan user, lalu jelaskan alasannya.

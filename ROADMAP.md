# Roadmap

Urutan fase ini mengikuti prioritas di `PRD.md`. Jangan mulai fase berikutnya sebelum kriteria selesai fase sebelumnya terpenuhi, kecuali ada keputusan eksplisit untuk mengubah urutan (catat di `CHANGELOG.md`).

## Fase 0: Fondasi (Sebelum Kode Fitur Apapun)

Tujuan: kerangka proyek siap, keputusan arsitektur mengambang di `docs/ARCHITECTURE.md` bagian 6 sudah diputuskan.

Kriteria selesai:
- Workspace Cargo dengan struktur crate sesuai `docs/ARCHITECTURE.md` bagian 2 sudah dibuat, boleh kosong isinya dulu.
- Format IPC antara core dan CLI sudah diputuskan dan didokumentasikan.
- `cargo audit` dan `cargo deny` sudah tersetup di CI.
- CI dasar jalan (build, clippy, fmt check) untuk target Linux.

## Fase 1: Linux, Deteksi File Dasar

Tujuan: `vigil-core` bisa memantau filesystem dan melakukan hash/signature check dasar di Linux, tanpa fitur ransomware/DNS/network dulu.

Kriteria selesai:
- Sensor filesystem Linux (inotify minimal, fanotify sebagai target) terhubung ke `vigil-core`.
- Integrasi YARA-X dan hash reputation lokal berjalan.
- Decision Engine versi awal (tanpa behavior_score dulu, cukup static_score dan hash_reputation) mengembalikan Allow/Block/PromptUser.
- Tier 1 dan Tier 3 allowlist (`docs/DECISION_ENGINE.md`) berfungsi.
- Resource usage idle diukur dan didokumentasikan, dibandingkan terhadap target `PRD.md` bagian 6.1.
- Test EICAR (file test standar industri untuk uji antivirus, bukan malware sungguhan) terdeteksi dengan benar.

## Fase 2: Linux, Anti False Positive dan Ransomware

Tujuan: menambah kemampuan yang jadi pembeda utama Vigil.

Kriteria selesai:
- Honeypot file dan deteksi entropy shift untuk ransomware berfungsi.
- Tier 5 exclusion (`node_modules`, `.git`, `target`, dsb) berfungsi dengan sensitivity reduced, bukan disabled total.
- eBPF process monitoring via `aya` terintegrasi untuk `behavior_score`.
- Suite regresi false positive (`PRD.md` bagian 6.4) dijalankan dan lulus semua skenario untuk platform Linux.
- Learning mode saat instalasi (scan package manager, batch approve) berfungsi.

## Fase 3: Linux, DNS Filter dan Anti-Phishing

Kriteria selesai:
- DNS proxy via `hickory-dns` berjalan, dengan Tier 4 domain allowlist (`docs/DECISION_ENGINE.md`) mencegah tunnel developer ke-flag.
- Integrasi blocklist reputasi domain (URLhaus, PhishTank, atau setara) berfungsi.
- Overhead DNS proxy diukur, harus tidak menambah latency DNS yang terasa oleh user.
- **IP Reputation Filter** (`docs/ARCHITECTURE.md` bagian 3.8) terintegrasi lewat eBPF (`aya`), blok koneksi ke IP dari feed curated (Feodo Tracker, Spamhaus DROP/EDROP), dengan TTL entry lebih pendek dari domain blocklist. Diuji tidak salah tangkap IP milik CDN/cloud provider besar (skenario tambahan di suite regresi `PRD.md` bagian 6.4).
- **Deteksi resolver/proxy lain yang sudah aktif** (`systemd-resolved`, dnsmasq, Pi-hole, dnscrypt-proxy, dsb) berfungsi saat instalasi, dengan tiga mode integrasi (`takeover`/`chain_upstream`/`disabled`) tersaji jelas ke user, bukan gagal diam-diam atau memaksa mematikan setup yang sudah ada. Diuji khusus terhadap `systemd-resolved` karena paling umum ditemui di distro Linux modern.

## Fase 4: Browser Extension Companion

Tujuan: menutup gap visibilitas di dalam browser (phishing konten, in-page cryptomining) yang tidak bisa dijangkau monitoring level OS, lihat `docs/THREAT_MODEL.md` bagian 2.6 dan `docs/ARCHITECTURE.md` bagian 3.9. Bisa dikerjakan paralel dengan Fase 5/6 karena stack teknologinya berbeda (JS/TypeScript, bukan Rust) dan tidak menunggu port Windows/macOS, tapi butuh DNS Filter (Fase 3) sudah berjalan karena blocklist yang dipakai sama.

Kriteria selesai:
- `vigil-native-host` berfungsi sebagai jembatan native messaging ke IPC `vigil-core`, startup cepat dan ringan (diukur, bukan diasumsikan).
- **Extension ID sudah di-fix di awal fase** (`key` di manifest.json untuk Chrome, `browser_specific_settings.gecko.id` untuk Firefox), dan sudah ditulis ke host manifest native messaging sebelum development fitur dimulai, lihat `docs/ARCHITECTURE.md` bagian 3.9.1.
- **Submission MVP (cuma enforce blocklist) ke Chrome Web Store dan Firefox Add-ons sudah dikirim di awal fase**, bukan menunggu semua fitur selesai, supaya waktu review tidak jadi bottleneck di akhir.
- `vigil-browser-extension` versi Chrome/Edge (Manifest V3) dan Firefox (WebExtensions) berfungsi, enforce domain blocklist di page-load lewat `declarativeNetRequest`.
- Heuristik form-action-mismatch berfungsi dengan daftar `trusted_identity_providers` (`docs/CONFIG_SCHEMA.md`) sudah teruji tidak salah tangkap SSO/OAuth umum.
- Blocklist mining pool domain diintegrasikan, di-refresh lewat `vigil-core`, bukan fetch langsung dari ekstensi.
- Suite regresi false positive khusus browser (`PRD.md` bagian 6.4) dijalankan dan lulus: login Google/Microsoft/GitHub, situs dengan Google Ads/Analytics, dsb.
- Overhead content script diukur (target di bawah 50ms per page load) dan didokumentasikan.
- Privacy review: dikonfirmasi tidak ada URL/konten halaman yang terkirim ke server manapun selain lookup lokal lewat `vigil-core`.

## Fase 5: Data Breach Check (Opsional, Bisa Paralel dengan Fase 3/4)

Kriteria selesai:
- Credential leak check dengan skema k-anonymity berfungsi tanpa mengirim data mentah keluar mesin.
- Fitur clipboard/upload pattern detection, kalau diimplementasikan, defaultnya off dan butuh opt-in eksplisit dengan penjelasan jelas ke user soal privasi.

## Fase 6: CLI dan UX Notifikasi

Kriteria selesai:
- `vigil-cli` bisa menampilkan status daemon, riwayat keputusan (audit log), dan mengubah allowlist.
- Notifikasi native (Allow Once / Always Allow / Block) berfungsi di Linux desktop environment umum (GNOME, KDE, dan yang dipakai CachyOS default).
- **Batching notifikasi**: kalau banyak event ambigu (`PromptUser`) muncul hampir bersamaan dari sesi aktivitas yang sama (misal instalasi tool baru yang memicu beberapa proses/domain baru sekaligus), sistem wajib mengelompokkan jadi satu notifikasi ringkasan yang bisa ditinjau bersama, bukan membanjiri user dengan popup satu per satu. Detail teknis pengelompokan (berdasarkan window waktu, parent process, atau kombinasi keduanya) didesain saat fase ini dimulai, dicatat di `docs/DECISION_ENGINE.md` sebelum implementasi.

## Fase 7: Port ke Windows

Prasyarat: semua fase Linux di atas sudah stabil dan suite regresi false positive lulus konsisten selama periode tertentu (tentukan durasi konkret sebelum mulai fase ini, misal beberapa minggu penggunaan internal tanpa insiden false positive baru).

Kriteria selesai:
- Sensor Windows (ReadDirectoryChangesW, ferrisetw untuk ETW) terintegrasi lewat trait yang sama dari `docs/ARCHITECTURE.md` bagian 3.2.
- Suite regresi false positive dijalankan ulang khusus untuk skenario Windows (Windows Defender coexistence, Windows Update, dsb, tambahkan ke `PRD.md` bagian 6.4 kalau ada skenario spesifik Windows yang belum tercatat).
- Resource usage idle diukur ulang khusus Windows.

## Fase 8: Port ke macOS

Prasyarat: sama seperti Fase 7, plus kepastian soal status entitlement EndpointSecurity dari Apple (lihat `docs/THREAT_MODEL.md` bagian 4 dan `PRD.md` bagian 9 soal mitigasi kalau entitlement tidak didapat).

Kriteria selesai:
- Sensor macOS (FSEvents minimal, EndpointSecurity kalau entitlement didapat) terintegrasi.
- Mode terbatas terdokumentasi jelas kalau EndpointSecurity tidak tersedia.

## Prinsip Umum Lintas Fase

- Setiap fase yang menyentuh Decision Engine wajib menjalankan suite regresi false positive sebelum dianggap selesai, tidak terkecuali.
- Jangan menggabungkan pekerjaan multi-platform dalam satu fase kecuali disebutkan eksplisit di atas, ini untuk menjaga fokus dan memudahkan review.
- Update dokumen ini setiap kali fase selesai atau urutan berubah, supaya selalu mencerminkan kondisi nyata proyek.

# GN-Shield

Endpoint security agent yang ringan, ditulis dalam Rust, untuk melindungi dari malware, phishing/scam, ransomware, dan kebocoran data, tanpa mengganggu workflow developer sehari hari.

Status proyek: **Phase 0 (Foundation)**. Menyiapkan workspace Cargo, CI script build lokal, dan kontrak desain yang mengikat sebelum implementasi fitur dimulai.

## Kenapa Proyek Ini Ada

Tool keamanan endpoint yang ada sekarang umumnya berat (Windows Defender, CrowdStrike, dsb) atau ringan tapi terbatas fiturnya (ClamAV). GN-Shield menyasar celah di tengah: proteksi yang cukup lengkap (malware, ransomware, phishing, DLP dasar), tapi dengan jejak CPU dan memori seminimal mungkin, dan didesain sejak awal untuk tidak salah tangkap (false positive) terhadap tools developer seperti cloudflared, ngrok, Docker, atau browser.

## Target Platform

- Prioritas 1: Linux (khususnya Arch based seperti CachyOS)
- Prioritas 2: Windows
- Prioritas 3: macOS

Urutan ini menentukan urutan implementasi. Jangan mulai kerja platform 2 atau 3 sebelum platform 1 stabil, kecuali disebutkan lain di roadmap.

## Peta Dokumen

Baca dokumen dengan urutan ini kalau kamu baru di proyek ini (termasuk kalau kamu adalah AI agent):

1. `AGENTS.md`, aturan main untuk siapapun (manusia atau AI) yang mengubah kode atau desain di repo ini. **Wajib dibaca sebelum melakukan perubahan apapun.**
2. `PRD.md`, apa yang dibangun, untuk siapa, dan batasan scope.
3. `docs/THREAT_MODEL.md`, ancaman apa yang ditangani dan yang secara sadar tidak ditangani.
4. `docs/ARCHITECTURE.md`, bagaimana sistem disusun secara teknis.
5. `docs/DECISION_ENGINE.md`, spesifikasi mesin scoring dan allowlist yang jadi jantung sistem anti false-positive.
6. `docs/CONFIG_SCHEMA.md`, format konfigurasi TOML yang dipakai semua komponen.
7. `ROADMAP.md`, urutan pengerjaan dan definisi selesai per fase.
8. `CONTRIBUTING.md`, cara kerja praktis: struktur branch, review, testing.

## Prinsip Desain (ringkas)

Detail lengkap ada di `PRD.md` dan `AGENTS.md`, tapi tiga prinsip ini mengalahkan preferensi lain kalau ada konflik:

1. **Diam lebih baik daripada salah.** Sistem yang terlalu banyak alert palsu akan dimatikan penggunanya. Default ke arah tidak mengganggu, dengan jalur eskalasi yang jelas untuk kasus yang benar benar berbahaya.
2. **Hemat resource bukan fitur tambahan, itu syarat kelulusan.** Setiap fitur baru harus diukur dampaknya ke CPU dan memori idle sebelum dianggap selesai.
3. **User tetap pemegang keputusan akhir.** Sistem boleh merekomendasikan block, tapi block permanen tanpa jalur override manusia hanya untuk kasus dengan confidence sangat tinggi yang didefinisikan eksplisit di `docs/DECISION_ENGINE.md`.

## Struktur Repo

```
gn-shield/
  AGENTS.md
  PRD.md
  README.md
  ROADMAP.md
  CONTRIBUTING.md
  CHANGELOG.md
  build.sh
  docs/
    ARCHITECTURE.md
    THREAT_MODEL.md
    DECISION_ENGINE.md
    CONFIG_SCHEMA.md
  crates/            (struktur lengkap dan terkini ada di docs/ARCHITECTURE.md bagian 2)
    gn-shield-core/
    gn-shield-sensors-common/
    gn-shield-sensors-linux/
    gn-shield-sensors-windows/
    gn-shield-sensors-macos/
    gn-shield-rules/
    gn-shield-dns/
    gn-shield-storage/
    gn-shield-cli/
    gn-shield-config/
    gn-shield-native-host/
  browser-extension/ (proyek JS/TypeScript terpisah, lihat docs/ARCHITECTURE.md bagian 3.9)
```

Daftar crate di atas sengaja diringkas, bukan daftar lengkap, supaya README tidak perlu diupdate tiap kali struktur workspace berubah. **`docs/ARCHITECTURE.md` bagian 2 adalah sumber kebenaran tunggal untuk struktur workspace**, kalau ada perbedaan antara README ini dan `docs/ARCHITECTURE.md`, anggap `docs/ARCHITECTURE.md` yang benar dan laporkan README ini perlu diperbaiki.

## Status Implementasi

Belum ada kode. Lihat `ROADMAP.md` untuk fase berikutnya. Jangan menulis kode berdasarkan asumsi struktur yang belum tercatat di `docs/ARCHITECTURE.md`, tambahkan dulu ke dokumen itu, baru implementasi.

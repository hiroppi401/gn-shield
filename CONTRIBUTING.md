# Contributing

Dokumen ini menjelaskan cara kerja praktis sehari hari. Untuk aturan yang lebih mendasar soal batas wewenang dan prinsip desain, baca `AGENTS.md` dan `PRD.md` dulu.

## 1. Sebelum Membuat Perubahan

1. Baca urutan dokumen di `README.md` bagian Peta Dokumen kalau belum familiar dengan proyek.
2. Pastikan task yang dikerjakan tidak masuk area Non-Goals di `PRD.md` bagian 4.
3. Kalau task menyentuh Decision Engine, allowlist, atau kemampuan auto-action apapun, baca `docs/DECISION_ENGINE.md` secara penuh dulu.

## 2. Alur Kerja Branch

- `main`, selalu dalam kondisi bisa di-build dan lulus test.
- `feature/<nama-singkat>`, untuk pekerjaan fitur.
- `fix/<nama-singkat>`, untuk perbaikan bug.
- Jangan commit langsung ke `main`.

## 3. Sebelum Membuka Pull Request

Checklist wajib:

- [ ] `cargo fmt --check` lulus
- [ ] `cargo clippy --all-targets -- -D warnings` lulus
- [ ] `cargo test` lulus
- [ ] Kalau menambah dependency baru: `cargo audit` sudah dijalankan dan tidak ada advisory terbuka yang belum ditangani
- [ ] Kalau perubahan menyentuh jalur deteksi (signature, scoring, sensor): suite regresi false positive (`PRD.md` bagian 6.4) sudah dijalankan
- [ ] Kalau perubahan menyentuh resource usage (menambah thread, polling, dependency berat): pengukuran CPU/memory idle sebelum dan sesudah perubahan disertakan di deskripsi PR
- [ ] Dokumen terkait (`docs/ARCHITECTURE.md`, `docs/DECISION_ENGINE.md`, `docs/CONFIG_SCHEMA.md`) sudah diupdate kalau perubahan berdampak ke struktur atau perilaku yang didokumentasikan di sana

## 4. Format Deskripsi Pull Request

```
## Apa yang berubah
(satu dua kalimat)

## Kenapa
(alasan/task/issue terkait)

## Dampak ke prinsip inti (AGENTS.md bagian 1)
- Resource footprint: (terukur/tidak berdampak, sertakan angka kalau ada)
- False positive: (skenario apa yang diuji)
- Reversibilitas: (apakah menambah auto-action baru, kalau ya jelaskan kenapa masuk kategori confidence tinggi di DECISION_ENGINE.md)

## Test yang dijalankan
(daftar test dan hasilnya)

## Dokumen yang diupdate
(daftar file docs/ yang ikut berubah, atau "tidak ada" kalau memang tidak relevan)
```

## 5. Menambah Dependency Baru

1. Cek status crate secara langsung (rilis terbaru, maintenance aktif, advisory keamanan terbuka), jangan mengandalkan ingatan pribadi atau ingatan model AI yang bisa sudah usang.
2. Jalankan `cargo audit` setelah menambahkan.
3. Dokumentasikan alasan pemilihan di `docs/ARCHITECTURE.md` bagian 5 kalau ini termasuk dependency inti (signature engine, storage engine, sensor library).
4. Untuk dependency dengan status beta/pre-1.0, pin versi exact di `Cargo.toml` (bukan `^` atau `~`), dan catat di komentar kenapa perlu pinning.

## 6. Menulis Test untuk Kode Deteksi

- Untuk uji signature/antivirus, gunakan file test standar industri (EICAR test file) untuk kasus dasar, jangan menulis payload malware baru.
- Untuk uji false positive, gunakan skenario nyata dari `PRD.md` bagian 6.4 (install package asli, clone repo asli, jalankan tunnel asli di lingkungan test terisolasi).
- Untuk uji ransomware detector, gunakan simulasi mass file write dengan data dummy, bukan ransomware sungguhan, meski dari sumber "riset".

## 7. Melaporkan Bug False Positive

Kalau menemukan false positive (dari testing atau laporan user):

1. Catat detail lengkap: aplikasi apa, versi, platform, dan sinyal apa yang membuatnya ke-flag (bisa dilihat dari audit log, lihat `docs/DECISION_ENGINE.md` bagian 7).
2. Tambahkan sebagai test case baru di suite regresi sebelum memperbaiki, supaya regresi yang sama tidak terjadi lagi di masa depan.
3. Perbaikan boleh berupa penambahan allowlist default (kalau tool tersebut memang legitimate dan umum dipakai) atau penyesuaian scoring (kalau masalahnya di formula/threshold).

## 8. Gaya Komunikasi di Commit Message dan PR

- Jelaskan alasan (why), bukan cuma apa (what). Kode sudah menjelaskan "apa", commit message harus menjelaskan "kenapa".
- Kalau perubahan menyangkut keputusan yang berdampak ke false positive atau resource, sebutkan trade-off yang dipertimbangkan, bukan cuma solusi akhir yang dipilih.

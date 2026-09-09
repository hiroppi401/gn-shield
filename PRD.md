# PRD: GN-Shield, Lightweight Cross Platform Endpoint Security Agent

Versi dokumen: 0.1
Status: Draft, menunggu review sebelum implementasi dimulai
Pemilik: (isi nama/tim)

## 1. Ringkasan Masalah

Pengguna teknis (developer, power user, sysadmin skala kecil) butuh perlindungan endpoint terhadap malware, ransomware, phishing/scam, dan kebocoran data, tapi menghindari tool keamanan mainstream karena dua alasan:

1. Berat di CPU dan memori, mengganggu workflow terutama di laptop atau mesin dengan resource terbatas.
2. Terlalu banyak false positive terhadap tools developer (tunnel seperti cloudflared/ngrok, container runtime, package manager, browser dengan banyak proses), yang akhirnya membuat user mematikan proteksi sama sekali.

GN-Shield dibangun untuk mengisi celah ini: proteksi yang cukup lengkap, jejak resource serendah mungkin, dan desain anti false-positive sebagai fitur inti sejak hari pertama, bukan tambahan belakangan.

## 2. Target Pengguna

- Developer dan power user Linux, khususnya distribusi berbasis Arch (CachyOS disebut eksplisit oleh pemilik produk sebagai lingkungan utama).
- Pengguna yang juga menjalankan Windows dan/atau macOS dan ingin pengalaman serta tingkat proteksi yang konsisten di semua platform mereka.
- Bukan target: enterprise dengan kebutuhan compliance formal (SOC2, HIPAA, dsb), tim SOC yang butuh integrasi SIEM skala besar. Kebutuhan ini boleh dipertimbangkan di masa depan tapi tidak mendorong keputusan desain di versi awal.

## 3. Tujuan Produk

Urutan berdasarkan prioritas, bukan daftar rata:

1. Deteksi dan cegah ransomware sebelum kerusakan signifikan terjadi (prioritas tertinggi karena kerusakannya paling ireversibel).
2. Deteksi malware (file dan proses berbahaya) dengan overhead rendah.
3. Cegah phishing/scam di level jaringan (DNS dan URL reputation).
4. Cegah kebocoran data dasar (credential leak check, deteksi pola data sensitif keluar).
5. Minim false positive terhadap tools developer umum, dievaluasi sebagai kriteria kelulusan, bukan nice-to-have.
6. Resource footprint serendah mungkin saat idle, dengan target angka konkret di bagian 6.

## 4. Bukan Tujuan (Non-Goals)

Sebutkan eksplisit supaya AI agent atau kontributor baru tidak memperluas scope tanpa sadar:

- Bukan antivirus signature-database besar seperti ClamAV/Defender yang mencoba mendeteksi semua varian malware yang pernah ada. GN-Shield fokus pada pola perilaku (behavioral) plus signature untuk kasus yang sudah dikenal umum.
- Bukan SIEM atau platform threat hunting enterprise.
- Bukan replacement firewall penuh. GN-Shield mengamati dan memberi rekomendasi jaringan (DNS filtering, reputation), tapi bukan firewall stateful lengkap.
- Bukan EDR (Endpoint Detection and Response) tingkat enterprise dengan remote management multi-device terpusat, setidaknya tidak di fase awal. Kalau ini berubah, harus lewat revisi PRD, bukan keputusan implementasi diam diam.
- Tidak mencoba menutup 100 persen serangan APT (Advanced Persistent Threat) bertarget tinggi. Target realistis adalah opportunistic malware, ransomware umum, dan phishing masal.
- Browser extension companion (`docs/ARCHITECTURE.md` bagian 3.9) bukan pengganti ad-blocker, bukan DLP penuh terhadap konten halaman, bukan analisis ML/NLP untuk deteksi brand impersonation visual, dan tidak bisa mendeteksi ekstensi browser lain yang jahat (keterbatasan arsitektural browser, bukan pilihan desain). Lihat `docs/THREAT_MODEL.md` bagian 2.6 untuk cakupan lengkap dan batasannya.
- IP Reputation Filter (`docs/ARCHITECTURE.md` bagian 3.8) bukan firewall per-proses, bukan default-deny-lalu-allow-list, tidak ada kontrol berbasis port atau proses individual. Cakupannya sengaja sempit: deny-list terhadap IP yang sudah terkonfirmasi infrastruktur malware/C2 dikenal. Memperluas ke firewall per-proses penuh adalah perubahan scope besar yang butuh keputusan produk eksplisit terpisah, bukan perkembangan bertahap dari fitur ini.

## 5. Ancaman yang Ditangani

Ringkas di sini, detail penuh dan justifikasi ada di `docs/THREAT_MODEL.md`.

| Kategori | Cakupan GN-Shield |
|---|---|
| Malware | Static signature (YARA-X), hash reputation, heuristik entropy, anomali struktur binary |
| Ransomware | Deteksi mass file modification, honeypot/canary file, entropy shift |
| Phishing/scam | DNS filtering, URL/domain reputation, deteksi domain baru terdaftar, diperkuat lewat browser extension companion untuk enforcement di page-load dan heuristik form-action-mismatch |
| Data breach | Credential leak check (k-anonymity), deteksi pola data sensitif di clipboard/upload (opsional, harus transparan ke user) |
| Supply chain attack (npm/cargo/pip) | Static scan tetap penuh di folder dependency, behavior monitoring khusus postinstall/prepare script, lihat `docs/THREAT_MODEL.md` bagian 2.5 |
| Browser-based (phishing konten, in-page cryptomining) | Browser extension companion (`gn-shield-browser-extension`), lihat `docs/THREAT_MODEL.md` bagian 2.6 dan `docs/ARCHITECTURE.md` bagian 3.9 |
| Bypass DNS Filter (koneksi langsung IP, DoH ke resolver luar) | IP Reputation Filter, blok koneksi ke IP dikenal C2/malware terlepas dari cara IP itu ditemukan, lihat `docs/ARCHITECTURE.md` bagian 3.8 |

**Catatan penting soal exclusion direktori development**: exclusion untuk `node_modules`, `.git`, `target`, dan sejenisnya yang disebutkan di bagian 6.4 HANYA berlaku untuk detektor ransomware (mengurangi sensitivitas terhadap mass file write saat install/build), bukan untuk static malware scan atau process behavior monitoring. Kedua lapisan itu tetap wajib aktif penuh di semua direktori tanpa kecuali. Ini untuk memastikan package yang terkena supply chain attack tetap bisa terdeteksi. Lihat `docs/DECISION_ENGINE.md` bagian Batas Cakupan Tier 5 untuk detail teknisnya.

## 6. Requirement Non-Fungsional (Wajib, Bukan Aspirasi)

Ini bagian paling sering diabaikan proyek keamanan lain. Di GN-Shield, angka ini adalah kriteria lulus/gagal untuk setiap rilis.

### 6.1 Resource

- CPU idle (tidak ada event aktif): target di bawah 1 persen rata rata pada mesin modern 4 core.
- Memory resident saat idle: target di bawah 100 MB untuk daemon inti (belum termasuk database signature yang dimuat sesuai kebutuhan, bukan semua di memori).
- Saat scanning aktif (misal on-access scan file besar): CPU boleh naik, tapi harus ada throttle/queue supaya tidak membuat sistem terasa lag untuk user.
- Binary size: usahakan di bawah 20 MB per komponen sebelum kompresi, dengan `opt-level = "z"` dan LTO aktif untuk build rilis.
- **Ukuran ruleset YARA-X**: setiap penambahan rule signature wajib diukur dampaknya ke memory resident (ruleset terkompilasi ikut dihitung), diperlakukan sama seperti menambah dependency baru di `AGENTS.md`. Tidak ada angka absolut tetap di sini karena tergantung isi rule, tapi penambahan yang mendorong memory idle melebihi target di atas wajib ditolak atau rule-nya dikurasi ulang, bukan target yang dilonggarkan begitu saja.
- **Beban skala (load test)**: sistem harus tetap memenuhi target CPU/memory di atas saat diuji dengan skenario beban tinggi, bukan cuma kondisi idle satu file. Skenario minimum: extract archive berisi 10.000+ file kecil dalam waktu singkat, `npm install` project dengan dependency tree besar, dan `git clone` repo besar. CPU boleh naik sementara selama proses berlangsung, tapi wajib turun kembali ke baseline idle segera setelah beban selesai, tidak boleh ada memory yang tidak kembali turun (indikasi leak) setelah beban selesai.
- **Disk I/O idle**: saat tidak ada event aktif, tidak boleh ada write berkala yang signifikan ke disk di luar batching audit log terjadwal (`docs/ARCHITECTURE.md` bagian 3.5). Diukur lewat tool monitoring I/O (`iotop` atau setara) selama periode idle yang cukup panjang (misal 1 jam), dibandingkan dengan baseline sistem tanpa GN-Shield berjalan.

### 6.2 False Positive

- Target false positive rate terhadap daftar "known developer tools" (lihat `docs/DECISION_ENGINE.md` bagian default allowlist) adalah nol dari hasil out-of-the-box, bukan setelah user konfigurasi manual.
- Setiap kali user memilih "Always Allow" pada prompt, keputusan itu harus konsisten diingat selamanya untuk hash/path yang sama, tidak boleh tanya ulang.
- Setiap rilis baru wajib diuji terhadap suite regresi false positive (daftar aplikasi di bagian 6.4) sebelum dianggap release-ready.

### 6.3 Latency Keputusan

- Untuk file yang match hash allowlist (whitelisted), keputusan izin harus instan, idealnya di bawah 1 ms, karena ini di jalur hot-path on-access scan.
- Untuk kasus yang butuh scoring penuh, target di bawah 50 ms untuk file berukuran wajar (di bawah 50 MB).

### 6.4 Suite Regresi False Positive (wajib ada sebelum rilis publik)

Daftar minimum aplikasi/skenario yang harus lolos tanpa alert yang mengganggu user:

- Firefox dan Chromium (multi proses, banyak koneksi jaringan)
- cloudflared (tunnel, subdomain acak trycloudflare.com)
- ngrok
- Tailscale
- Docker/Podman (build image, banyak file baru di overlay filesystem)
- git clone repo besar, dan git checkout yang mengubah banyak file
- npm install / cargo build / pip install (banyak file baru di node_modules, target, venv)
- Package manager sistem (pacman, apt) saat update besar
- **Browser extension**: form login legitimate dengan SSO/OAuth pihak ketiga (login lewat Google, Microsoft, GitHub) tidak boleh ke-flag oleh heuristik form-action-mismatch. Situs dengan iklan/analytics umum (Google Ads, Google Analytics, dsb) tidak boleh ke-flag oleh blocklist mining pool. Content script ekstensi tidak boleh menambah latency yang terasa saat page load (target di bawah 50ms overhead, diukur lewat Performance API browser).
- **IP Reputation Filter**: koneksi ke IP milik CDN/cloud provider besar (Cloudflare, AWS, GCP, Azure edge IPs) yang kebetulan pernah tercatat di feed reputasi (karena shared hosting/multi-tenant) tidak boleh diblokir kalau IP tersebut sudah tidak aktif di feed terbaru (TTL bekerja dengan benar). Koneksi VPN/Tailscale/tunnel developer (`docs/DECISION_ENGINE.md` Tier 4) tidak boleh terpengaruh oleh layer ini.
- **IPv6**: setiap skenario di atas yang melibatkan jaringan (DNS Filter, IP Reputation Filter) wajib diuji ulang lewat jalur IPv6, bukan cuma IPv4. Koneksi ke IP blocklist yang diakses lewat IPv6 harus terdeteksi/terblokir sama seperti lewat IPv4, dan domain yang di-allowlist harus tetap lolos meski resolusinya lewat AAAA record.
- **Fan-out proses**: membuka Firefox/Chromium dengan banyak tab sekaligus, dan menjalankan beberapa container Docker/Podman bersamaan, tidak boleh memicu sinyal "mass child spawning" di `behavior_score` (`docs/DECISION_ENGINE.md` bagian 10). Sebaliknya, proses yang sengaja membuat banyak child process cepat TANPA berasal dari lineage trusted (`high_fanout_expected`) harus tetap terdeteksi sebagai sinyal mencurigakan.
- **Containment**: simulasi proses yang di-flag confidence tinggi harus melalui urutan freeze-isolate-observe-terminate (`docs/DECISION_ENGINE.md` bagian 9) tanpa membuat sistem hang melebihi anggaran latency, dan child process yang di-spawn proses tersebut selama jendela observasi harus ikut ter-contain tanpa memengaruhi proses lain yang tidak terkait.
- **Cryptomining vs compute berat legitimate**: proses render (Blender), training ML, atau compile besar dengan CPU tinggi berkelanjutan TIDAK boleh ter-flag hanya karena penggunaan CPU-nya, selama tidak ada sinyal lain (koneksi mencurigakan, tidak ada hash reputation dikenal). Sebaliknya, proses miner yang di-download dengan CPU tinggi DAN koneksi ke domain/IP mining pool dikenal harus tetap terdeteksi.

## 7. User Flow Utama

### 7.1 Instalasi dan Learning Mode

Saat instalasi pertama, sistem melakukan scan aplikasi terinstal via package manager, mencocokkan dengan default allowlist bawaan, dan menyodorkan daftar untuk di-approve user secara batch, bukan satu per satu di hari pertama pakai.

### 7.2 Deteksi Confidence Tinggi (auto block)

Untuk kasus dengan confidence sangat tinggi sesuai definisi di `docs/DECISION_ENGINE.md` (contoh: hash cocok persis dengan database malware dikenal, atau pola ransomware yang sangat spesifik seperti mass encryption plus perubahan pada honeypot file), sistem boleh bertindak otomatis (block/quarantine proses) dan baru memberi tahu user sesudahnya, karena menunggu konfirmasi manusia di kasus ini berisiko kerusakan ireversibel.

### 7.3 Deteksi Confidence Menengah (tanya user)

Untuk kasus ambigu, seperti tunnel baru yang belum ada di allowlist, sistem menampilkan notifikasi non-blocking dengan pilihan Allow Once, Always Allow, dan Block. Sistem tidak boleh memblokir proses secara default sebelum user menjawab, kecuali proses tersebut sedang melakukan aksi yang juga masuk kategori confidence tinggi secara terpisah.

### 7.4 Override dan Audit

User harus bisa melihat riwayat keputusan (log allow/block) dan mengubahnya kapan saja lewat CLI atau file config. Semua keputusan otomatis harus tercatat dengan alasan yang bisa dibaca manusia, bukan cuma skor angka.

### 7.5 Uninstall

GN-Shield mengubah beberapa konfigurasi sistem (resolver DNS diarahkan ke GN-Shield, host manifest native messaging untuk browser, hook kernel eBPF/WFP/Network Extension). Uninstall WAJIB mengembalikan semua perubahan ini ke kondisi semula, bukan sekadar menghapus binary:
1. Kembalikan resolver DNS sistem ke konfigurasi sebelum GN-Shield terinstal. Ini kritis, kalau terlewat, sistem kehilangan resolusi DNS sepenuhnya setelah GN-Shield dihapus karena resolver masih menunjuk ke `127.0.0.1`/`[::1]` yang sudah tidak ada yang melayani.
2. Hapus host manifest native messaging (`docs/ARCHITECTURE.md` bagian 3.9) supaya browser tidak lagi mencoba connect ke binary yang sudah tidak ada.
3. Unload/bersihkan hook kernel (program eBPF di Linux, filter WFP di Windows, konfigurasi Network Extension di macOS) secara bersih, jangan tinggalkan state menggantung.
4. Tanya user soal file yang masih dikarantina (`docs/DECISION_ENGINE.md` bagian 9): tawarkan untuk restore atau hapus permanen, jangan diam-diam dihapus begitu saja sebagai bagian dari cleanup uninstall, karena itu bisa jadi bukti false positive yang belum sempat ditinjau.
5. Hapus service/daemon registration (systemd unit, Windows Service, launchd plist) dengan bersih.

## 8. Metrik Keberhasilan

- Nol laporan false positive dari suite regresi (bagian 6.4) di setiap rilis.
- CPU idle dan memory idle memenuhi target di bagian 6.1, diverifikasi dengan benchmark otomatis, bukan perkiraan.
- Waktu dari deteksi ransomware pattern sampai proses dihentikan, diukur dan didokumentasikan per rilis.

## 9. Batasan dan Asumsi

- GN-Shield berasumsi user punya hak admin/root untuk instalasi (perlu akses kernel-level monitoring seperti eBPF, ETW, EndpointSecurity).
- GN-Shield tidak menjamin proteksi terhadap ancaman zero day yang sepenuhnya baru dan tidak menunjukkan pola perilaku mencurigakan apapun.
- Dukungan macOS bergantung pada ketersediaan entitlement EndpointSecurity dari Apple, yang butuh proses approval terpisah di luar kendali proyek ini. Rencanakan mitigasi (mode terbatas) di `docs/ARCHITECTURE.md` bila entitlement tidak didapat.
- **GN-Shield dirancang untuk mesin single-primary-user** (satu developer/power user utama per perangkat, sesuai target pengguna di bagian 2). Skenario mesin dipakai bergantian oleh beberapa manusia berbeda (shared workstation) belum didesain penuh, khususnya soal apakah entry allowlist (Tier 1-4) berlaku per-user atau system-wide. Field `locked_fields` di `docs/CONFIG_SCHEMA.md` menangani kasus admin vs user biasa di satu mesin yang sama, tapi bukan solusi lengkap untuk multi-user shared machine. Kalau target pengguna berkembang ke arah itu, ini butuh keputusan desain terpisah sebelum diimplementasikan, bukan diasumsikan otomatis bekerja.

## 10. Proses Perubahan Dokumen Ini

Perubahan pada bagian 3 (Tujuan Produk), 4 (Non-Goals), dan 6 (Requirement Non-Fungsional) dianggap perubahan besar dan harus dicatat di `CHANGELOG.md` dengan alasan perubahan. AI agent yang bekerja di repo ini tidak berwenang mengubah bagian bagian tersebut tanpa instruksi eksplisit dari pemilik produk, lihat `AGENTS.md` bagian batas wewenang.

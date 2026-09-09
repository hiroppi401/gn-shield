# Threat Model

Dokumen ini mendefinisikan ancaman apa yang secara sadar ditangani GN-Shield, ancaman apa yang secara sadar tidak ditangani (dan kenapa), serta aktor/skenario yang jadi acuan desain.

## 1. Profil Penyerang yang Diasumsikan

GN-Shield dirancang untuk melawan:

- Malware opportunistic yang menyebar luas (bukan malware custom yang dibuat khusus menyasar satu individu).
- Ransomware umum yang dijual sebagai layanan (Ransomware-as-a-Service) dan variannya.
- Kampanye phishing masal (bukan spear-phishing yang sangat personal dan diteliti mendalam terhadap target tertentu).
- Kebocoran credential akibat reuse password di berbagai layanan yang pernah bocor (covered lewat breach database check).

GN-Shield **tidak** dirancang untuk melawan:

- Nation-state actor atau APT dengan sumber daya besar dan exploit zero day custom.
- Serangan fisik terhadap perangkat (evil maid attack, dsb).
- Insider threat dari user yang sengaja menonaktifkan proteksi.
- **Rootkit/kernel-level hiding**: teknik yang menyembunyikan proses/file dari API sistem normal (hooking syscall table, DKOM/Direct Kernel Object Manipulation, dsb) secara eksplisit di luar cakupan v1. Sensor GN-Shield (eBPF/ETW/EndpointSecurity) mengasumsikan API sistem yang dipakainya melaporkan data yang jujur, kalau lapisan itu sendiri sudah disusupi rootkit, GN-Shield tidak akan tahu. Ini bukan celah yang dilupakan, ini keputusan scope yang sama dengan alasan tidak menutup APT bertarget tinggi.

Alasan pembatasan ini: melawan APT butuh sumber daya riset dan update ancaman yang jauh melampaui kapasitas proyek ini, dan mencoba mengklaim proteksi terhadap itu justru memberi rasa aman palsu (false sense of security) ke user.

## 2. Kategori Ancaman dan Mekanisme Deteksi

### 2.1 Malware (file dan proses berbahaya)

**Vektor**: file executable, script, atau library berbahaya yang dijalankan atau dimuat di sistem.

**Mekanisme deteksi**:
- Hash matching terhadap database reputasi (lokal cache, opsional query eksternal seperti MalwareBazaar).
- Static pattern matching dengan YARA-X untuk signature yang sudah dikenal.
- Heuristik entropy untuk deteksi binary yang di-pack/dienkripsi secara mencurigakan.
- Parsing struktur binary (PE/ELF/Mach-O) untuk anomali header yang lazim dipakai teknik evasion.

**Batasan sadar**: tidak melakukan sandboxing/dynamic analysis penuh (menjalankan file di lingkungan terisolasi untuk observasi perilaku) di versi awal, karena ini mahal secara resource dan bertentangan dengan requirement lightweight. Bisa dipertimbangkan sebagai fitur opsional/opt-in di masa depan, dicatat di `ROADMAP.md`, bukan default.

### 2.2 Ransomware

**Vektor**: proses yang melakukan enkripsi massal terhadap file user, biasanya diikuti permintaan tebusan.

**Mekanisme deteksi**:
- Monitoring pola mass file modification dalam window waktu singkat.
- Honeypot/canary file: file umpan diletakkan di direktori umum, kalau berubah maka ini sinyal kuat.
- Entropy shift: file yang tadinya berupa teks/format dikenal berubah jadi random tinggi entropy adalah indikator enkripsi.
- Integrasi dengan snapshot filesystem kalau tersedia (Btrfs/ZFS di Linux, VSS di Windows, Time Machine API di macOS) untuk auto-rollback.

**Batas cakupan auto-rollback (penting, supaya tidak overclaim)**: GN-Shield TIDAK mengelola jadwal snapshot-nya sendiri (di luar scope, itu tanggung jawab tool/OS seperti `snapper`/`timeshift` di Linux, VSS di Windows, Time Machine di macOS). GN-Shield murni MENDETEKSI apakah infrastruktur snapshot yang kompatibel sudah ada dan aktif di sistem, dan kalau ada, MENAWARKAN rollback ke snapshot pre-insiden terakhir sebagai bagian dari notifikasi setelah containment (`docs/DECISION_ENGINE.md` bagian 9). Kalau tidak ada snapshot yang kompatibel/aktif, GN-Shield tidak bisa melakukan rollback apapun, hanya mengandalkan containment plus quarantine. Ini harus dikomunikasikan jelas ke user sebagai batasan (idealnya direkomendasikan saat instalasi supaya user mengaktifkan snapshot berkala sendiri), bukan diklaim sebagai jaminan recovery penuh.

**Batasan sadar**: deteksi berbasis pola berarti ada risiko file besar yang di-encode/dikompresi secara legitimate (misal video editing, backup terenkripsi yang disengaja user) bisa memicu sinyal serupa. Ini yang membuat exclusion path untuk direktori development (`node_modules`, `.git`, `target`, dsb, lihat `docs/DECISION_ENGINE.md`) krusial, bukan opsional.

### 2.3 Phishing dan Scam

**Vektor**: link berbahaya yang mengarah ke situs credential harvesting atau scam, biasanya lewat email, chat, atau iklan.

**Mekanisme deteksi**:
- DNS-level filtering terhadap domain yang masuk blocklist reputasi (mirip Pi-hole tapi terintegrasi).
- URL reputation check terhadap database publik (Google Safe Browsing, PhishTank, URLhaus).
- Deteksi domain yang baru terdaftar (newly registered domain), karena ini pola umum kampanye phishing jangka pendek.
- **IP Reputation Filter** (`docs/ARCHITECTURE.md` bagian 3.8) sebagai lapisan pelengkap, bukan pengganti: DNS Filter beroperasi di level resolusi nama domain, sehingga bisa dilewati kalau malware connect langsung ke IP yang di-hardcode atau memakai DNS-over-HTTPS ke resolver publik yang melewati resolver lokal GN-Shield sepenuhnya. IP Reputation Filter menutup celah ini dengan mengecek reputasi di level koneksi, independen dari bagaimana IP tujuan ditemukan.

**Batasan sadar**: tidak melakukan parsing/analisis konten halaman web secara mendalam di level daemon (terlalu berat), fokus di level domain, URL, dan IP reputation. IP Reputation Filter sendiri hanya mencakup IP yang sudah masuk feed curated (Feodo Tracker, Spamhaus DROP/EDROP, dsb), bukan cakupan lengkap semua infrastruktur jahat yang mungkin ada, dan IP yang baru dipakai jahat butuh waktu sampai masuk feed (jendela waktu yang sama seperti keterbatasan domain reputation di atas).

### 2.4 Data Breach / Kebocoran Data

**Vektor**: credential yang sudah bocor di breach sebelumnya dan dipakai ulang, atau data sensitif yang keluar dari mesin secara tidak sengaja.

**Mekanisme deteksi**:
- Cek credential terhadap database breach memakai skema k-anonymity (seperti pendekatan Have I Been Pwned), sehingga password/email mentah user tidak pernah dikirim ke luar mesin.
- Deteksi pola data sensitif (nomor kartu kredit, API key) di clipboard atau traffic upload, sebagai fitur opsional yang harus transparan dan bisa dimatikan user karena menyentuh privasi.

**Batasan sadar**: ini bukan DLP (Data Loss Prevention) enterprise penuh. Cakupannya sengaja dasar dan opsional.

### 2.5 Supply Chain Attack Lewat Package Manager

**Vektor**: package pihak ketiga (npm, cargo, pip, dan sejenisnya) yang sudah disusupi malware, biasanya lewat salah satu dari tiga pola berikut:

1. Malicious postinstall/prepare script yang otomatis jalan saat proses install, tanpa user sadar sedang mengeksekusi kode.
2. Typosquatting, nama package sengaja dibuat mirip package populer supaya salah ketik user berujung install package berbahaya.
3. Maintainer account compromise, package yang sebelumnya bersih dan bereputasi baik tiba tiba dirilis versi baru berisi malware. Ini kasus paling sulit karena hash reputation lama tidak relevan untuk versi baru yang belum pernah dianalisis siapapun.

**Kenapa ini penting dibahas terpisah**: direktori seperti `node_modules` masuk exclusion list Tier 5 di `docs/DECISION_ENGINE.md` untuk mengurangi sensitivitas detektor ransomware (supaya `npm install` yang menulis ribuan file kecil dalam waktu singkat tidak salah tangkap). Exclusion ini **tidak boleh** ditafsirkan sebagai alasan untuk mematikan static scanning atau behavior monitoring di direktori tersebut. Lihat `docs/DECISION_ENGINE.md` bagian Batas Cakupan Tier 5 untuk penjelasan lengkap kenapa dua hal ini harus dipisah secara arsitektural.

**Mekanisme deteksi**:
- Static scan (YARA-X, hash reputation) tetap berjalan penuh terhadap semua file baru di `node_modules` atau folder dependency package manager lain, tanpa exclusion apapun.
- Process behavior monitoring memantau eksekusi postinstall/prepare script secara khusus, karena ini titik eksekusi kode pertama yang paling umum dipakai malware supply chain. Sinyal mencurigakan meliputi: akses ke direktori kredensial (`~/.ssh`, `~/.aws`, browser credential store), koneksi keluar ke domain yang tidak dikenal segera setelah install, atau download dan eksekusi binary tambahan yang tidak ada di package asli.
- Opsional untuk versi lanjutan (bukan wajib fase awal): integrasi dengan database reputasi package (misal advisory dari OSV, GitHub Advisory Database, atau layanan sejenis) untuk memberi peringatan sebelum install kalau versi package yang akan diinstall sudah dilaporkan bermasalah.

**Batasan sadar**: GN-Shield tidak melakukan analisis statis terhadap source code package (misal parsing JavaScript untuk mendeteksi obfuscated code) di versi awal, karena ini mahal secara resource dan rawan false positive terhadap teknik minifikasi/bundling yang legitimate. Fokus deteksi ada di titik eksekusi (behavior saat script benar benar jalan), bukan di titik baca kode statis package.

### 2.6 Ancaman Berbasis Browser (Phishing Konten, In-Page Cryptomining)

**Vektor**: ancaman yang muncul di dalam konten halaman web atau tab browser, di mana monitoring level OS (eBPF/ETW) tidak punya visibilitas karena secara struktural tidak bisa membedakan tab/halaman/script mana yang sedang berjalan di dalam satu proses browser. Kategori ini secara sadar ditutup lewat komponen terpisah, `gn-shield-browser-extension` (lihat `docs/ARCHITECTURE.md` bagian 3.9), bukan lewat monitoring OS.

**Sub-kategori**:
1. **Phishing berbasis domain yang sudah dikenal**: ditangani DNS Filter (bagian 2.3) dan diperkuat di level ekstensi lewat `declarativeNetRequest`/`webRequest` blocking, memberi UX lebih jelas dibanding sekadar kegagalan resolusi DNS.
2. **Phishing lewat form login yang mencurigakan**: content script ekstensi mengecek form dengan input password yang submit ke origin berbeda dari halaman saat ini, dengan pengecualian eksplisit untuk identity provider legitimate (OAuth/SSO umum) supaya flow login normal tidak salah tangkap.
3. **Cryptomining di dalam halaman (in-page JavaScript/WASM miner)**: ditangani lewat blocklist domain/endpoint mining pool dikenal (feed `coinblockerlists`, `docs/CONFIG_SCHEMA.md`) yang di-enforce ekstensi, bukan lewat profiling CPU per-tab (tidak reliable lintas browser, lihat `docs/ARCHITECTURE.md` bagian 3.9 untuk penjelasan kenapa). Cakupan ini sama untuk miner berbasis WASM maupun JS biasa, karena deteksinya di level tujuan jaringan (domain/endpoint), bukan berdasarkan cara implementasi kodenya.

**Batasan sadar (penting, supaya tidak overclaim)**:
- Phishing yang benar-benar baru (zero day, domain belum pernah masuk blocklist manapun, dan tidak memicu heuristik form-action-mismatch, misal karena tidak ada input password atau memakai teknik lain) tidak akan tertangkap sampai reputasinya diperbarui lewat Update Service.
- GN-Shield tidak bisa mendeteksi ekstensi browser lain yang jahat, karena browser mengisolasi ekstensi satu sama lain secara arsitektural, tidak ada API yang memberi visibilitas cross-extension. Satu-satunya cakupan untuk ekstensi jahat adalah static scan file ekstensi di disk lewat mekanisme malware biasa (bagian 2.1), bukan lewat `gn-shield-browser-extension`.
- Tidak ada analisis konten berbasis ML/NLP untuk deteksi brand impersonation visual. Heuristik yang dipakai sengaja sederhana dan bisa dijelaskan, bukan model black-box, konsisten dengan prinsip lightweight proyek ini.

### 2.7 Malware Fileless / Living-off-the-Land (LOLBins)

**Vektor**: kode berbahaya yang dieksekusi TANPA pernah menyentuh disk sebagai file terpisah, sehingga tidak ada apapun untuk di-hash atau di-scan YARA-X. Dua pola utama:
1. **One-liner interpreter/LOLBins**: perintah dijalankan langsung lewat argumen command-line (`powershell -enc <base64>`, `bash -c "..."`, `certutil -decode`, `mshta http://...`, `rundll32 javascript:...`), memakai binary yang sah (living-off-the-land) untuk menjalankan payload yang di-encode/obfuscate di dalam argumen itu sendiri.
2. **Process injection**: kode disuntikkan ke memory proses lain yang sedang berjalan (misal lewat `CreateRemoteThread`+`WriteProcessMemory` di Windows, `ptrace` di Linux, `task_for_pid` di macOS), proses target yang legitimate jadi menjalankan kode jahat tanpa file baru apapun muncul di disk.

**Kenapa ini penting diakui eksplisit**: seluruh mekanisme deteksi utama GN-Shield (Tier 1 hash, YARA-X static scan) beroperasi di level FILE. Teknik fileless secara struktural melewati kedua mekanisme itu sepenuhnya, karena memang tidak ada file yang bisa dijadikan subjek pemeriksaan.

**Mitigasi yang didesain (parsial, bukan solusi penuh)**:
1. **Command-line argument sebagai "dokumen virtual"**: argumen command-line proses yang baru dieksekusi ikut dilewatkan ke YARA-X sebagai teks yang discan, bukan cuma isi file binary-nya. Pattern dikenal untuk LOLBins abuse (base64 payload panjang di argumen powershell, pola `certutil -decode`, `mshta` dengan URL, dsb) bisa dideteksi lewat rule YARA-X yang sama, reuse engine yang sudah ada tanpa komponen baru.
2. **Deteksi process injection sebagai sinyal `behavior_score` baru**: memantau indikator injeksi klasik lewat sensor yang sudah ada (ETW di Windows untuk pola `CreateRemoteThread`/`WriteProcessMemory` ke proses lain, eBPF di Linux untuk pola `ptrace` mencurigakan ke proses lain, EndpointSecurity di macOS untuk `task_for_pid` abuse). Proses legitimate yang tiba-tiba memiliki memory region executable asing ter-map adalah sinyal kuat.

**Batasan yang diakui jujur**: ini tetap masalah deteksi yang jauh lebih sulit dibanding malware berbasis file, teknik fileless yang canggih (terutama yang dirancang khusus menghindari pola LOLBins/injection yang sudah dikenal) berpotensi tetap lolos. Ini konsisten dengan `PRD.md` Non-Goals soal tidak mengklaim proteksi penuh terhadap APT bertarget tinggi, mitigasi di sini menaikkan bar deteksi untuk kasus umum/opportunistic, bukan menutup celah sepenuhnya.

## 3. False Positive Sebagai Ancaman Tersendiri

Perlakukan false positive sebagai kategori risiko sendiri, bukan sekadar bug kecil. Alasan: sistem keamanan yang sering salah tangkap terhadap tools legitimate (cloudflared, Docker, browser, package manager) akan membuat user mematikan proteksi sepenuhnya, yang berarti risiko nyata (malware, ransomware sungguhan) jadi tidak tertangani sama sekali. Detail mekanisme mitigasi ada di `docs/DECISION_ENGINE.md`.

## 4. Batasan Platform

- **Linux**: akses penuh lewat eBPF dan fanotify/inotify, tingkat visibilitas paling tinggi di antara tiga platform.
- **Windows**: tergantung ETW (Event Tracing for Windows) untuk visibilitas proses/network, tidak sedalam kernel driver custom (minifilter), yang secara sadar dihindari di versi awal karena kompleksitas dan risiko stabilitas sistem kalau driver bermasalah.
- **macOS**: tergantung EndpointSecurity Framework yang butuh entitlement khusus dari Apple. Kalau entitlement tidak didapat, GN-Shield di macOS berjalan dengan visibilitas terbatas (FSEvents saja, tanpa deep process monitoring), ini harus dikomunikasikan jelas ke user sebagai batasan, bukan disembunyikan.

## 5. Serangan yang Menyasar GN-Shield Sendiri (Tamper Resistance)

Malware dan ransomware yang lebih matang sering mencoba mematikan atau melumpuhkan proses antivirus/EDR terlebih dulu sebelum beraksi (misal langsung `kill` proses, menghapus service, atau memodifikasi konfigurasi supaya deteksi mati). Ini kategori ancaman tersendiri yang harus diakui eksplisit, bukan diasumsikan tidak ada.

**Cakupan v1 (sengaja terbatas, bukan diabaikan)**:
- Daemon `gn-shield-core` dijalankan lewat service manager (`systemd` di Linux, Service Control Manager di Windows, `launchd` di macOS) dengan `Restart=always` atau setara, supaya proses yang mati (baik karena crash maupun sengaja dimatikan) otomatis restart, ini baseline minimum, bukan proteksi penuh.
- Permission file konfigurasi dan database (`docs/CONFIG_SCHEMA.md`, storage rusqlite) dikunci hanya bisa ditulis oleh user dengan privilege admin/root, supaya proses berjalan biasa (non-privileged) tidak bisa memodifikasi allowlist atau menghapus audit log secara langsung.
- Audit log mencatat kalau daemon berhenti tidak wajar (bukan lewat shutdown normal) dan menampilkan ini di `gn-shield-cli status`, supaya user sadar kalau ada percobaan mematikan proteksi, walau sistem tidak bisa mencegahnya secara aktif di v1.

**Yang secara sadar TIDAK dicakup di v1** (technique-level self-defense seperti protected process, anti-debugging terhadap proses sendiri, kernel-level self-protection driver): ini butuh kompleksitas dan risiko stabilitas yang signifikan (terutama driver custom di Windows yang sudah secara sadar dihindari, lihat bagian 4), jadi didorong ke roadmap lanjutan setelah fondasi platform utama stabil, bukan janji yang dibuat sekarang. Catat progresnya di `ROADMAP.md` kalau fase ini dimulai.

## 6. Update Threat Model

Dokumen ini harus direvisi setiap kali kategori ancaman baru ditambahkan atau mekanisme deteksi utama berubah signifikan. Perubahan di sini berdampak ke `PRD.md` bagian 5, jadi update keduanya bersamaan.

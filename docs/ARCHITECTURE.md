# Architecture

## 1. Gambaran Umum

GN-Shield terdiri dari beberapa komponen terpisah yang berkomunikasi lewat IPC lokal, bukan satu binary monolitik. Alasan pemisahan ini murni resource management: UI/CLI yang berat (rendering, dsb) tidak boleh membebani daemon inti yang harus selalu ringan dan berjalan di background.

```
                    +-------------------+
                    |   gn-shield-cli / |
                    |   gn-shield-ui    |
                    +---------+---------+
                              | IPC (local socket / named pipe)
                    +---------v---------+
                    |   gn-shield-core  |
                    |  (daemon utama)   |
                    +---------+---------+
                              |
        +---------------------+---------------------+
        |                     |                       |
+-------v-------+   +---------v---------+   +--------v--------+
| Decision Engine|   | Signature/Rule     |   | Update Service  |
| (scoring +     |   | Store (YARA-X,     |   | (threat intel,  |
| allowlist)     |   | hash reputation)   |   | signature diff) |
+-------+--------+   +--------------------+   +-----------------+
        |
+-------v----------------------------------------+
|            Sensor Abstraction Layer              |
| (trait bersama, implementasi per platform)        |
+---+-----------------+-----------------+----------+
    |                 |                 |
+---v---+       +-----v-----+     +-----v-----+
| Linux |       | Windows   |     | macOS     |
| sensor|       | sensor    |     | sensor    |
+-------+       +-----------+     +-----------+
```

## 2. Struktur Workspace Rust (Rencana)

```
gn-shield/
  Cargo.toml                 (workspace root)
  build.sh                   (script build/verifikasi lokal)
  crates/
    gn-shield-core/           daemon utama, decision engine, IPC server
    gn-shield-sensors-common/ trait abstraksi sensor lintas platform
    gn-shield-sensors-linux/  implementasi fanotify/inotify + eBPF (aya)
    gn-shield-sensors-windows/ implementasi ReadDirectoryChangesW + ETW (ferrisetw)
    gn-shield-sensors-macos/  implementasi FSEvents + EndpointSecurity
    gn-shield-rules/          wrapper YARA-X, hash reputation, entropy check
    gn-shield-dns/            DNS proxy/filter (hickory-dns)
    gn-shield-storage/        wrapper rusqlite untuk semua persistent state
    gn-shield-cli/            command line client
    gn-shield-config/         parsing dan validasi TOML config (lihat CONFIG_SCHEMA.md)
    gn-shield-native-host/    jembatan native messaging ke IPC lokal, dipakai browser extension
  browser-extension/          proyek JS/TypeScript terpisah (WebExtension), TIDAK masuk workspace Cargo, lihat bagian 3.9
```

Catatan penting: struktur ini adalah rencana, bukan fakta yang sudah diimplementasikan. Kalau kamu AI agent yang membaca ini dan crate di atas belum ada, jangan asumsikan sudah ada, cek dulu dengan melihat isi repo aktual.

## 3. Komponen Inti

### 3.1 gn-shield-core (daemon)

Bertanggung jawab atas:
- Menerima event dari sensor layer.
- Meneruskan event ke Decision Engine untuk scoring.
- Mengeksekusi aksi (allow/block/prompt) hasil keputusan.
- Menyediakan IPC server untuk CLI/UI.

Berjalan sebagai background service (systemd service di Linux, Windows Service di Windows, launchd di macOS). Dirancang event-driven memakai `tokio`, bukan polling, untuk menjaga CPU idle tetap rendah.

### 3.2 Sensor Abstraction Layer

Trait bersama supaya logic di `gn-shield-core` tidak perlu tahu detail platform:

```rust
pub trait FileSystemSensor {
    fn watch(&mut self, path: &Path) -> Result<(), SensorError>;
    fn next_event(&mut self) -> Result<FsEvent, SensorError>;
}

pub trait ProcessSensor {
    fn subscribe(&mut self) -> Result<(), SensorError>;
    fn next_event(&mut self) -> Result<ProcessEvent, SensorError>;
}

pub trait NetworkSensor {
    fn subscribe(&mut self) -> Result<(), SensorError>;
    fn next_event(&mut self) -> Result<NetworkEvent, SensorError>;
}
```

Implementasi konkret:

| Platform | Filesystem | Process | Network |
|---|---|---|---|
| Linux | fanotify/inotify (crate `notify`, atau langsung via `nix` untuk kontrol lebih halus) | eBPF via `aya` | netlink socket |
| Windows | `ReadDirectoryChangesW` (via crate `notify`) | ETW via `ferrisetw` | Windows Filtering Platform |
| macOS | FSEvents (via crate `notify`) | EndpointSecurity Framework (butuh entitlement Apple) | Network Extension framework |

Sensor Network di ketiga platform wajib memonitor kedua address family (AF_INET/IPv4 dan AF_INET6/IPv6), bukan cuma IPv4, supaya data yang masuk ke `behavior_score` dan ke IP Reputation Filter (bagian 3.8) lengkap dari awal, tidak ada blind spot di sisi observasi yang baru ketahuan setelah enforcement diimplementasikan.

### 3.3 Decision Engine

Detail penuh ada di `docs/DECISION_ENGINE.md`. Ringkasnya, komponen ini menerima sinyal dari beberapa sumber (static signature match, hash reputation, behavior score, allowlist override) dan menghasilkan satu dari tiga aksi: Allow, Block, atau PromptUser. Allowlist override selalu menang di atas sinyal lain.

### 3.4 Signature/Rule Store

- YARA-X untuk pattern matching (pure Rust, tidak ada FFI ke C, lihat justifikasi pemilihan di bagian 5).
- Hash reputation cache lokal, dengan opsi query eksternal (rate-limited) ke layanan seperti MalwareBazaar.
- Rule di-update lewat Update Service secara delta (hanya kirim perubahan, bukan seluruh database tiap kali) untuk hemat bandwidth dan CPU saat parsing.
- **Public Suffix List (PSL) untuk DNS filter juga masuk sebagai artifact yang dikelola Update Service ini**, disegarkan berkala lewat mekanisme yang sama dengan signature dan hash reputation, bukan proses terpisah yang butuh rebuild binary. Lihat bagian 3.7 untuk detail arsitektur dua lapis (compiled-in fallback plus dinamis).

#### 3.4.1 Strategi Scanning Bertingkat (Wajib, Bukan Optimisasi Opsional)

Ini bagian paling kritis untuk memenuhi target resource di `PRD.md` bagian 6.1, khususnya karena ruleset YARA-X bisa tumbuh besar seiring waktu. Scanning TIDAK BOLEH diimplementasikan sebagai "cocokkan tiap file terhadap seluruh ruleset setiap kali file disentuh". Implementasi wajib melalui pipeline berlapis berikut, diurutkan dari termurah ke termahal, berhenti secepat mungkin begitu keputusan bisa diambil:

**Layer 0, short-circuit berbasis hash (O(1), sebelum YARA-X disentuh sama sekali)**:
1. Cek hash file terhadap allowlist (Tier 1/2/3/3b di `docs/DECISION_ENGINE.md`). Kalau trusted, langsung Allow, jangan sentuh YARA-X.
2. Cek hash terhadap database reputasi dikenal jahat. Kalau match, langsung Block, jangan sentuh YARA-X.
3. Cek **verdict cache**: kalau hash file ini sudah pernah discan dengan versi ruleset yang sama persis dan hasilnya tersimpan, pakai hasil cache, jangan scan ulang. Ini krusial untuk direktori seperti `node_modules` yang isinya sering berupa file identik terduplikasi lintas project. Cache wajib disimpan sebagai (hash, ruleset_version) -> verdict, dan otomatis invalid kalau ruleset_version berubah (supaya update signature tetap bisa menangkap ulang file yang sebelumnya lolos).

**Layer 1, pre-filter murah (sebelum full pattern matching)**:
1. Cek magic bytes/tipe file. Mayoritas rule malware menyasar executable, script, dokumen bermacro, bukan semua tipe file. Tipe file yang jelas bukan kandidat (gambar, teks polos tanpa anomali struktural) tidak perlu masuk full YARA pass kecuali dipicu sinyal lain.
2. Scan hanya dipicu oleh event Create/Write/Exec dari sensor filesystem, bukan Read. File yang dibaca ulang tanpa berubah tidak memicu scan baru.
3. File di atas ambang ukuran tertentu (`max_scan_file_size_mb` di config) discan lewat `mmap` dan/atau dijadwalkan ke antrian prioritas rendah di background, bukan blocking di jalur on-access.

**Catatan kritis soal TOCTOU (Time-Of-Check-Time-Of-Use)**: sensor filesystem berbasis notifikasi pasif (`inotify`, `FSEvents`, `ReadDirectoryChangesW` versi notify) punya celah waktu antara file discan dan file benar-benar dieksekusi, di mana attacker secara teori bisa menukar isi file di antara dua titik itu (symlink race atau file replace cepat) untuk melewati hasil scan yang sudah dianggap aman. Ini keterbatasan yang melekat pada scanning berbasis notifikasi di kebanyakan tool AV/EDR, bukan cuma GN-Shield, tapi wajib ditangani sebisa mungkin, bukan diabaikan:
- **Linux**: WAJIB memakai `fanotify` dalam mode permission event (`FAN_OPEN_EXEC_PERM`), bukan cuma notify pasif, khusus untuk event Exec. Mode ini menahan (block) syscall `execve` sampai `gn-shield-core` memberi keputusan izin, menutup celah race sepenuhnya untuk kasus eksekusi. Trade-off yang diterima sadar: menambah latency di titik eksekusi (harus tetap dalam anggaran `PRD.md` bagian 6.3), dan risiko hang kalau scanner lambat/macet wajib dimitigasi lewat timeout wajib (kalau `gn-shield-core` tidak merespons dalam waktu tertentu, default ke Allow supaya sistem tidak freeze, dicatat sebagai keputusan fail-open yang disengaja khusus di titik ini, beda dari prinsip fail-closed di tempat lain, karena membekukan seluruh sistem jauh lebih buruk daripada celah race yang sempit).
- **macOS**: EndpointSecurity Framework mendukung event otorisasi (`ES_EVENT_TYPE_AUTH_EXEC`) yang juga bersifat blocking, dipakai dengan prinsip yang sama seperti fanotify permission mode di atas.
- **Windows**: ETW pada dasarnya notify-only (pasif), tidak punya mekanisme blocking setara tanpa kernel driver custom (minifilter) yang sudah secara sadar dihindari (`docs/ARCHITECTURE.md` bagian 3.2, tabel sensor Network/Process). Ini artinya **Windows punya residual TOCTOU risk yang diakui secara eksplisit sebagai keterbatasan**, bukan diklaim sudah tertutup penuh. Mitigasi parsial: perkecil window race dengan memprioritaskan scan file baru secepat mungkin di antrian (bagian Layer 4), meski tidak menghilangkan race sepenuhnya. Kalau kebutuhan menutup celah ini sepenuhnya di Windows meningkat prioritasnya di masa depan, itu berarti mempertimbangkan ulang keputusan menghindari minifilter driver, perubahan besar yang harus didiskusikan eksplisit, bukan ditambahkan diam diam.

**Kapabilitas tambahan: gating dinamis per-PID (bukan cuma global)**: mekanisme permission event di atas (`FAN_OPEN_EXEC_PERM`/`ES_EVENT_TYPE_AUTH_EXEC`) juga jadi fondasi untuk containment di `docs/DECISION_ENGINE.md` bagian 9. Implementasi wajib mendukung penambahan/pencabutan gate secara dinamis untuk PID spesifik saat runtime (bukan cuma aturan global yang berlaku sama untuk semua proses), supaya saat sebuah proses di-flag confidence tinggi, `gn-shield-core` bisa langsung memblokir write/unlink lebih lanjut KHUSUS dari PID itu tanpa memengaruhi proses lain yang sedang berjalan.

**Layer 2, ruleset dikompilasi sekali, dipakai berulang**:
YARA-X mengompilasi rule menjadi struktur matching internal (bukan re-parse teks `.yar` per file). Kompilasi ini terjadi HANYA saat daemon startup atau saat rule diupdate lewat Update Service, hasilnya (compiled ruleset) tetap resident di memori dan dipakai untuk semua scan berikutnya. Simpan juga bentuk terkompilasi ke disk (YARA-X mendukung serialisasi compiled rules) supaya restart daemon tidak perlu compile ulang dari teks mentah setiap kali, ini juga memangkas disk read banyak file kecil saat startup. Implementasi yang mengompilasi ulang ruleset per file yang discan adalah bug performa serius, bukan trade-off yang diterima.

**Layer 3, kurasi ukuran ruleset, bukan impor mentah**:
Jangan mengimpor ruleset komunitas besar (beberapa paket publik berisi puluhan ribu rule, dirancang untuk threat hunting retrospektif skala besar, bukan real-time endpoint agent yang ringan) tanpa kurasi. Sesuai `PRD.md` bagian 4 (Non-Goals), GN-Shield secara sadar bukan AV dengan cakupan signature selengkap mungkin, jadi menambah rule ke ruleset harus melalui proses yang sama seperti menambah dependency baru di `AGENTS.md`: diukur dampaknya ke memory/CPU sebelum dianggap selesai, bukan ditambahkan bebas tanpa batas. Lihat `PRD.md` bagian 6.1 untuk NFR pengukuran ukuran ruleset.

**Layer 4, prioritas OS-level untuk scan worker**:
Scan worker pool wajib berjalan di prioritas scheduling rendah (`nice`/`ionice` di Linux, Below Normal priority class di Windows, QoS background di macOS), supaya scan tidak pernah berebut CPU atau I/O dengan kerja interaktif user di foreground. `scan_queue_max_concurrent` (lihat `docs/CONFIG_SCHEMA.md`) defaultnya adaptif terhadap jumlah core (`max(1, num_cpus / 4)`), bukan angka tetap yang sama di semua mesin, dan wajib mundur (backoff) otomatis kalau load rata-rata sistem sedang tinggi dari aplikasi lain.

**Layer 5, update rule tidak memicu full disk rescan**:
Saat ruleset diupdate lewat Update Service, JANGAN scan ulang seluruh disk secara otomatis sebagai efek samping. Update signature hanya memengaruhi file yang dilihat sensor SETELAH update terjadi, atau file yang statusnya masih tersimpan sebagai "belum final/dipertanyakan" di cache verdict. Full disk sweep berkala boleh ada sebagai fitur terpisah yang off by default dan harus dipicu eksplisit oleh user, bukan otomatis jalan tiap kali signature baru datang, supaya tidak menimbulkan disk read/write masif tanpa disadari.

#### 3.4.2 Keputusan Arsitektur: Atribusi PID untuk Phased Containment pada Jalur Filesystem/Ransomware (Telah Diimplementasikan via Opsi 1)

**Konteks Temuan & Gap Arsitektur:**
Sesuai bagian 4 dokumen ini dan `docs/DECISION_ENGINE.md` bagian 9, deteksi confidence tinggi (honeypot berubah + anomali entropy shift + kecepatan modifikasi di atas threshold) wajib menjalankan alur containment (`contain_and_terminate_process()`) dengan membekukan (freeze via SIGSTOP) proses penyerang sebelum melakukan terminasi (SIGKILL) dan karantina file. Namun, pada implementasi awal, sensor filesystem Linux mengalirkan event melalui enum `FsEvent::Created/Modified/Deleted` yang hanya membawa path file tanpa informasi PID (`None`). Akibatnya, pemanggilan `execute_scan_verdict(&eval, None)` dan `execute_incident_action(&incident, None)` di loop daemon tidak pernah menghentikan proses yang sedang aktif mengenkripsi disk — file korban memang dikarantina, tetapi proses malware-nya sendiri tetap dibiarkan berjalan bebas.

Untuk menutup celah ini dan menyediakan PID penyerang ke ActionExecutor, dua opsi teknis utama dianalisis:

1. **Opsi 1: Atribusi Kernel-Native via Fanotify Event Metadata (`fanotify_event_metadata.pid` / `FAN_REPORT_PIDFD` / `FAN_REPORT_TID`)**
   - **Mekanisme**: Fanotify di Linux secara native menyertakan PID proses pemanggil dalam struct `fanotify_event_metadata` per event. Sensor menangkap event `FAN_MODIFY | FAN_CLOSE_WRITE | FAN_OPEN_EXEC_PERM`, membaca PID pemanggil asli secara langsung dari kernel tanpa polling atau probing tambahan, dan meneruskannya ke `FsEvent`.
   - **Resource Footprint saat Idle (`AGENTS.md` Prinsip 1)**: Sangat optimal. O(1) buffer read, tidak ada syscall traversal tambahan.
   - **Risiko False-Positive (`AGENTS.md` Prinsip 2)**: Sangat rendah. PID diperoleh langsung dari konteks syscall kernel yang memicu modifikasi file, menghilangkan risiko salah tangkap proses developer non-jahat.
   - **Kompatibilitas OS & Kernel**: Menggunakan standard Linux fanotify metadata (Linux >= 5.1).

2. **Opsi 2: Heuristik User-Space Cross-Reference `/proc/[pid]/fd`** (Ditolak)
   - Ditolak karena overhead CPU/IO masif saat burst modifikasi file dan tingginya risiko false-positive (TOCTOU) terhadap developer tools (IDE/compilers).

**Keputusan & Implementasi Final**:
Opsi 1 telah disetujui pemilik produk dan diimplementasikan:
- `FsEvent` pada `gn-shield-sensors-common` diperluas dengan field `pid: Option<u32>`.
- `LinuxFsSensor` membaca PID langsung dari `fanotify_event_metadata` dan mengalirkan event file modify/exec dengan atribut PID.
- `RansomwareDetector` dan `main.rs` daemon loop meneruskan PID proses penyerang ke `ActionExecutor::execute_incident_action(&incident, target_pid)` dan `ActionExecutor::execute_scan_verdict(&eval, pid)`, memastikan proses penyerang di-contain (freeze SIGSTOP + terminate SIGKILL) dengan tetap mematuhi perlindungan safety guard (PID 0, PID 1, self-PID) dan circuit breaker.

### 3.5 Storage

Semua state persisten (allowlist, hash cache, riwayat keputusan/audit log) disimpan lewat `rusqlite`. Satu file database per instalasi, lokasinya mengikuti konvensi OS masing masing (`$XDG_DATA_HOME` di Linux, `%APPDATA%` di Windows, `~/Library/Application Support` di macOS).

**Batching write untuk menghindari disk I/O berlebihan**: audit log dan verdict cache (lihat 3.4.1 Layer 0) berpotensi menulis banyak baris kecil kalau setiap event langsung di-commit sinkron ke disk. Wajib pakai SQLite WAL (Write-Ahead Logging) mode dan batching (kumpulkan beberapa event lalu commit sekaligus dalam satu transaksi, dengan interval singkat, misal tiap beberapa ratus milidetik atau tiap N event, mana yang lebih dulu tercapai), bukan satu transaksi per event. Ini penting khusus untuk requirement "tidak ada disk read/write masif" karena daemon ini jalan 24/7, penulisan sinkron per-event dalam jangka panjang bisa jadi sumber I/O yang tidak disadari. WAL mode juga memberi manfaat tambahan untuk stabilitas: commit bersifat atomik, jadi kalau daemon crash di tengah batch write, database tidak berakhir dalam state korup, transaksi yang belum selesai otomatis di-rollback saat storage dibuka kembali.

**Asumsi enkripsi at-rest**: GN-Shield TIDAK mengimplementasikan enkripsi sendiri untuk file storage/database-nya. Perlindungan data at-rest (kalau perangkat dicuri/hilang) diasumsikan jadi tanggung jawab enkripsi disk level OS (LUKS di Linux, BitLocker di Windows, FileVault di macOS), yang jauh lebih tepat untuk lapisan ini dibanding GN-Shield menambah lapisan enkripsi sendiri (yang toh butuh key yang harus disimpan/diakses di mesin yang sama, tidak menambah proteksi berarti terhadap threat model yang relevan di sini). Permission file (bagian sebelumnya, dan `docs/THREAT_MODEL.md` bagian 5) tetap jadi lapisan utama terhadap akses oleh proses lain yang berjalan di mesin yang sama.

### 3.6 Update Service

Komponen ini sengaja dipisahkan sebagai subsection sendiri (bukan cuma disebut sepintas di 3.4), karena secara keamanan ini adalah salah satu bagian paling sensitif di seluruh sistem: Update Service adalah satu-satunya jalur yang bisa mengubah signature YARA-X, hash reputation, default allowlist, dan PSL, yang semuanya berarti **mengubah keputusan trust di seluruh GN-Shield**. Kalau jalur ini bisa disusupi, penyerang bisa mendorong "update" palsu yang menambahkan malware ke allowlist atau menghapus signature deteksi tertentu, dan GN-Shield sendiri jadi vektor serangan alih-alih alat proteksi.

**Requirement wajib**:
1. Semua artifact update (signature YARA-X, hash reputation delta, default-allowlist.toml, PSL) harus **ditandatangani secara kriptografis** (misal Ed25519 lewat `minisign` atau setara) oleh key milik proyek, dan **diverifikasi signature-nya sebelum diterapkan**. Public key verifikasi ini ikut ter-bundle di dalam binary GN-Shield sendiri (bukan didownload dari server yang sama dengan update-nya, supaya tidak ada single point of compromise).
2. Download lewat HTTPS, dan idealnya pinning terhadap certificate/public key tertentu untuk endpoint update resmi, supaya MITM di jaringan tidak cukup untuk mengelabui proses download.
3. Update diterapkan secara atomik: tulis ke file sementara dulu, verifikasi checksum dan signature, baru rename/swap menggantikan file lama. Kalau verifikasi gagal di titik manapun, batalkan seluruh proses dan tetap pakai versi lama (fail closed ke data lama yang diketahui baik, konsisten dengan prinsip yang sama di `docs/ARCHITECTURE.md` bagian 3.7 soal PSL).
3a. **Proteksi rollback/replay**: verifikasi signature saja TIDAK CUKUP, karena attacker bisa me-replay artifact lama yang signature-nya masih valid tapi sudah usang/deprecated (misal versi ruleset lama yang punya celah bypass yang sudah diperbaiki di versi baru). Setiap artifact wajib membawa nomor versi atau timestamp monoton yang ikut ditandatangani, dan `gn-shield-core` WAJIB menolak menerapkan update dengan versi/timestamp lebih lama atau sama dengan yang sudah terpasang, meski signature-nya valid. Prinsip ini sama dengan yang dipakai framework update security seperti TUF (The Update Framework).
4. Riwayat versi update yang berhasil diterapkan dicatat di audit log yang sama dengan keputusan Allow/Block, supaya kalau ada masalah, bisa ditelusuri update mana yang aktif saat insiden terjadi.
5. Strategi pull berkala (bukan push/webhook) untuk versi awal, dengan interval yang wajar (misal beberapa jam sekali, bukan tiap menit), supaya tidak menambah beban network/CPU idle. **Wajib memakai conditional HTTP request** (`ETag`/`If-None-Match` atau `Last-Modified`/`If-Modified-Since`), supaya kalau tidak ada perubahan sejak pengecekan terakhir, server cukup membalas `304 Not Modified` (beberapa ratus byte, bukan payload penuh), bukan mengulang download seluruh data tiap siklus. Ini dipilih dibanding WebSocket/push karena jauh lebih sederhana dan robust untuk daemon yang jalan 24/7 (tidak perlu reconnect logic untuk kasus laptop sleep/wake, ganti jaringan, NAT timeout, dsb, yang semuanya otomatis beres sendiri karena HTTP stateless per-request), dengan trade-off yang diterima sadar: update mendesak (misal signature ransomware baru) menunggu sampai siklus pull berikutnya, bukan diterima instan. Kalau kebutuhan latency rendah untuk update mendesak jadi prioritas di masa depan, pertimbangkan Server-Sent Events sebagai jalur tambahan khusus untuk kategori update urgent, bukan mengganti seluruh mekanisme jadi WebSocket.
6. **Staleness warning berlaku untuk SEMUA artifact yang dikelola Update Service** (signature YARA-X, hash reputation, default-allowlist, PSL), bukan cuma PSL. Setiap artifact menyimpan timestamp refresh terakhir yang berhasil, ditampilkan di `gn-shield-cli status`, dengan ambang warning per jenis data (baseline: signature/hash reputation 7 hari, default-allowlist 30 hari, PSL 45 hari seperti sudah dicatat di bagian 3.7, angka berbeda karena kecepatan perubahan data yang berbeda). Ini supaya kegagalan pipeline update untuk artifact manapun terlihat jelas, tidak diam-diam membuat proteksi basi berbulan-bulan tanpa disadari siapapun.
7. **Keterbatasan rotasi signing key (diakui jujur, bukan diselesaikan penuh di v1)**: public key verifikasi di-bundle di dalam binary GN-Shield sejak build (poin 1). Kalau private key yang dipakai menandatangani update dicurigai bocor/compromised, tidak ada mekanisme rotasi otomatis di v1 (tidak ada hierarki key bertingkat ala TUF/The Update Framework). Mitigasi satu-satunya untuk skenario ini adalah merilis binary baru dengan public key baru dan meminta user upgrade manual, sama seperti software pada umumnya menangani kompromise key. Kalau threat model proyek berkembang sampai butuh proteksi rotasi key otomatis, itu perubahan arsitektural besar yang perlu didesain terpisah, dicatat di sini supaya tidak diasumsikan sudah tertangani.

### 3.7 DNS Filter

Berjalan sebagai local DNS proxy memakai `hickory-dns`. User mengarahkan resolver sistem ke GN-Shield (127.0.0.1 atau setara), GN-Shield meneruskan query ke upstream resolver setelah cek domain terhadap blocklist reputasi dan allowlist domain developer tools (lihat `docs/DECISION_ENGINE.md` untuk daftar default seperti `*.trycloudflare.com`).

**Wajib dual-stack (IPv4 dan IPv6), bukan IPv4-only**: listen di `127.0.0.1:53` DAN `[::1]:53`, dan filtering berlaku sama untuk query A record (IPv4) maupun AAAA record (IPv6). Ini bukan sekadar kelengkapan, ini celah bypass nyata: kalau filter cuma cek A record, malware/domain jahat bisa tetap lolos lewat AAAA record yang tidak pernah dicek. Sistem yang resolvernya diarahkan ke GN-Shield tapi aplikasi tertentu query lewat jalur IPv6 harus tetap ter-filter sama ketatnya.

**Upstream wajib terenkripsi/terautentikasi (DoT/DoH), bukan DNS polos**: komunikasi `gn-shield-core` ke resolver upstream (misal 1.1.1.1, 9.9.9.9) wajib memakai DNS-over-TLS atau DNS-over-HTTPS (`hickory-dns` mendukung keduanya), bukan UDP/TCP DNS biasa. Alasan: DNS polos rentan di-spoof oleh attacker on-path (misal di jaringan WiFi publik yang tidak dipercaya), yang bisa mengelabui balasan resolusi sebelum sampai ke GN-Shield, termasuk potensi downgrade attack (memalsukan balasan "bersih" untuk domain yang seharusnya diblokir). Tanpa ini, seluruh mekanisme blocklist domain bisa dilewati lewat manipulasi jaringan di titik upstream, bukan cuma di titik client.

**Komputasi eTLD+1 memakai dua lapis Public Suffix List (PSL), bukan satu sumber statis.** Ini penting supaya freshness PSL tidak terikat pada siklus rebuild/rilis binary, karena PSL berubah dari waktu ke waktu dan pipeline update yang bergantung pada manusia ingat untuk rebuild adalah titik kegagalan yang tidak reliable.

- **Lapis fallback (compiled-in)**: crate `psl`, PSL di-compile langsung jadi kode Rust native saat build. Selalu tersedia begitu binary terinstal, tidak butuh network sama sekali. Freshness-nya mengikuti siklus rilis normal proyek, bukan tindakan manual terpisah.
- **Lapis dinamis (runtime, dijaga fresh oleh Update Service)**: crate `publicsuffix`, mampu mem-parse file `public_suffix_list.dat` mentah di runtime tanpa compile ulang. File ini diperlakukan sebagai satu lagi artifact yang diambil Update Service (bagian 3.6), disegarkan berkala sama seperti signature YARA-X dan hash reputation, tanpa langkah manual apapun dari user atau developer.

Kedua crate mengimplementasikan trait `Psl` yang sama, jadi kode aplikasi cukup bergantung pada trait tersebut, tidak peduli backend mana yang sedang aktif.

**Urutan resolusi saat startup dan saat lookup**: cek dulu apakah ada file PSL hasil download Update Service yang valid dan berhasil di-parse. Kalau ada, pakai itu (lapis dinamis). Kalau tidak ada, kosong, atau gagal di-parse (corrupt, format berubah drastis, dsb), fallback otomatis ke lapis compiled-in. Prinsip yang dipakai adalah fail closed ke data lama yang diketahui baik, bukan fail open tanpa data PSL sama sekali, konsisten dengan prinsip validasi di `docs/CONFIG_SCHEMA.md` bagian 12.

**Deteksi staleness**: simpan timestamp kapan lapis dinamis terakhir berhasil di-refresh. Tampilkan di `gn-shield-cli status`, dan catat log warning kalau sudah melewati ambang tertentu (baseline: 45 hari) tanpa refresh berhasil. Ini supaya kegagalan pipeline update (misal server sumber PSL down, bukan soal lupa rebuild) tetap terlihat jelas ke user/operator, bukan diam-diam membuat data jadi basi tanpa disadari.

**Bukan single point of failure untuk resolusi DNS sistem**: kalau `gn-shield-core` crash, resolver sistem yang diarahkan penuh ke GN-Shield bisa membuat SELURUH resolusi DNS mesin ikut mati, jauh lebih mengganggu dibanding proteksi yang didapat. Mitigasi wajib: (1) DNS proxy harus jadi bagian yang startup-nya paling cepat dan paling prioritas untuk di-restart (`Restart=always` dengan delay minimal, lihat `docs/THREAT_MODEL.md` bagian 5), (2) instalasi dianjurkan tetap menyisakan resolver sekunder di konfigurasi sistem (bukan GN-Shield satu-satunya nameserver terdaftar) sebagai fallback kalau proses restart belum sempat selesai, ini trade-off yang diterima sadar antara proteksi maksimal vs jangan sampai kegagalan satu komponen melumpuhkan konektivitas dasar mesin.

**Integrasi dengan resolver/proxy yang sudah ada (wajib dideteksi, bukan diasumsikan tidak ada)**: banyak sistem Linux modern sudah menjalankan resolver sendiri sebelum GN-Shield terinstal (`systemd-resolved` yang umumnya bind di `127.0.0.53:53` dan mengelola `/etc/resolv.conf`, atau DNS proxy custom milik user seperti dnsmasq/Pi-hole/dnscrypt-proxy). GN-Shield TIDAK BOLEH mengasumsikan dirinya selalu jadi satu-satunya resolver, itu bisa menyebabkan port conflict (`bind()` gagal) atau merusak diam-diam fitur resolver lain (mDNS/LLMNR di systemd-resolved, ad-blocking di Pi-hole yang sudah dikonfigurasi user). Tiga mode integrasi wajib didukung, dipilih lewat `dns_filter.integration_mode` (`docs/CONFIG_SCHEMA.md`):

1. **`takeover`** (default kalau instalasi mendeteksi tidak ada resolver/proxy lain yang aktif): GN-Shield jadi resolver utama seperti desain di atas, mengubah `resolv.conf` mengarah ke dirinya.
2. **`chain_upstream`** (kalau instalasi mendeteksi resolver/proxy lain sudah aktif dan user memilih mempertahankannya): GN-Shield TIDAK berebut port 53. GN-Shield listen di port lokal alternatif, dan resolver/proxy yang sudah ada dikonfigurasi menunjuk ke GN-Shield sebagai upstream-nya (untuk `systemd-resolved`, ini lewat `resolvectl dns <interface> <alamat_gn_shield>`, mempertahankan fitur native systemd-resolved lain seperti mDNS/LLMNR yang tidak direplikasi GN-Shield). Filtering keamanan GN-Shield tetap berlaku di titik sebelum resolusi final ke internet, tanpa mengganggu setup resolver yang sudah dipilih user.
3. **`disabled`** (kalau integrasi tidak memungkinkan/user memilih tidak mengaktifkan): DNS Filter mati sepenuhnya. Ini TIDAK berarti kehilangan proteksi jaringan total, karena IP Reputation Filter (bagian 3.8) beroperasi independen dari DNS (memang didesain begitu sejak awal untuk kasus bypass), dan browser extension (bagian 3.9) tetap enforce blocklist di level page-load terlepas dari resolver sistem. Ini validasi konkret kenapa desain berlapis penting, satu lapis nonaktif, lapis lain tetap memberi proteksi.

**Deteksi wajib saat instalasi**: sebelum mencoba bind port 53, GN-Shield wajib mengecek proses/service apa yang sudah menguasai port tersebut atau mengelola `resolv.conf` (`systemd-resolved`, `NetworkManager`, proses lain yang listen di `127.0.0.1:53`/`127.0.0.53:53`), dan menyajikan pilihan mode integrasi ke user secara eksplisit lewat installer/CLI, bukan memaksa salah satu mode atau gagal diam-diam dengan pesan error teknis yang membingungkan.

### 3.8 IP Reputation Filter (Anti-Bypass DNS)

Komponen baru, dipilih secara sadar sebagai jalan tengah, bukan firewall per-proses penuh gaya Little Snitch/OpenSnitch (terlalu banyak prompt, risiko alert fatigue) dan bukan cuma DNS Filter saja (bisa di-bypass). **Alasan dibutuhkan**: DNS Filter (bagian 3.7) beroperasi murni di level resolusi nama domain, sehingga bisa dilewati dengan dua cara: (1) malware connect langsung ke IP yang di-hardcode tanpa lewat resolusi DNS sama sekali, atau (2) malware pakai DNS-over-HTTPS ke resolver publik yang di-hardcode, melewati resolver lokal GN-Shield sepenuhnya. Layer ini menutup celah itu dengan mengecek reputasi di level koneksi (IP address), independen dari bagaimana IP tujuan itu ditemukan.

**Kenapa dua lapis (domain DAN IP), bukan cukup salah satu**: keduanya menyasar pola infrastruktur yang berbeda, saling melengkapi bukan redundan.
- **Domain-based (DNS Filter) lebih presisi untuk phishing**, karena phishing sering numpang di shared hosting (banyak domain berbeda satu IP/server yang sama, termasuk situs legitimate yang di-hack). Blok berdasarkan IP di kasus ini berisiko ikut memblokir domain-domain legitimate lain yang tidak bersalah di server yang sama, blok berdasarkan domain jauh lebih surgical.
- **IP-based (layer ini) lebih presisi untuk malware C2**, karena infrastrukturnya sering pakai fast-flux DNS (satu domain rotasi ke banyak IP berbeda) atau bahkan tanpa domain sama sekali (hardcoded IP). Blocklist IP curated (Feodo Tracker, dsb) menangkap pola ini yang tidak akan pernah terlihat kalau cuma andalkan domain reputation.
- Kombinasi keduanya menutup kedua pola sekaligus, dan IP Reputation Filter secara khusus menutup celah bypass yang tidak bisa ditutup DNS Filter sendirian (lihat penjelasan di atas).

**Cakupan yang dibatasi sengaja (supaya tidak jadi firewall penuh)**:
- HANYA blok koneksi ke IP yang sudah terkonfirmasi di feed reputasi malware/C2 (deny-list terhadap infrastruktur jahat yang dikenal), BUKAN default-deny-lalu-allow-list seperti firewall per-proses.
- Tidak ada kontrol per-proses ("proses X boleh akses network atau tidak"), tidak ada rule berbasis port, tidak ada NAT/rule chain kompleks. Kalau ada dorongan menambah kapasitas ke arah itu di masa depan, itu perubahan scope besar yang wajib lewat proses yang sama seperti keputusan Browser Extension Companion (bagian 3.9), didiskusikan eksplisit dulu, bukan berkembang diam diam dari fitur ini.
- Tidak ada prompt ke user per koneksi. Match ke IP reputasi jahat masuk kategori confidence tinggi yang auto-block, sama seperti hash malware dikenal, lihat `docs/DECISION_ENGINE.md` bagian 5. Ini yang membuat layer ini tidak menambah alert fatigue seperti firewall per-proses.

**Sumber data**: feed reputasi IP yang curated khusus infrastruktur C2/malware (misal Feodo Tracker, Spamhaus DROP/EDROP), BUKAN broad abuse list yang noise-nya tinggi. Diperlakukan sebagai artifact Update Service seperti yang lain (bagian 3.6), termasuk staleness warning yang sama.

**Wajib mencakup IPv6, bukan cuma IPv4**: data model blocklist, feed reputasi, dan hook enforcement (poin di bawah) semuanya wajib mendukung alamat IPv6, bukan cuma IPv4. Kalau layer ini cuma menutup IPv4, itu justru membuka celah bypass baru yang persis sama dengan yang coba ditutup fitur ini, malware tinggal pakai koneksi IPv6 ke infrastruktur yang sama dan lolos sepenuhnya. Ini bukan detail sekunder, ini syarat inti supaya fitur ini benar-benar menutup celah, bukan cuma menutup sebagian.

**TTL lebih pendek dari domain blocklist**: alamat IP jauh lebih sering berpindah tangan/di-recycle dibanding domain (IP yang tadinya dipakai C2 bisa saja diberikan ulang ke layanan cloud legitimate beberapa minggu kemudian). Entry di blocklist IP wajib punya TTL lebih pendek (baseline 7-14 hari) dibanding entry domain, dan otomatis expire kalau tidak dikonfirmasi ulang oleh feed sumbernya, supaya tidak memblokir layanan legitimate yang kebetulan kebagian IP bekas.

**Override allowlist**: kalau IP yang di-flag ternyata milik layanan legitimate (kasus jarang tapi mungkin karena TTL di atas), user bisa menambah entry IP/CIDR eksplisit ke allowlist (`network.ip_allowlist`, perluasan dari Tier 4 di `docs/DECISION_ENGINE.md`), yang override keputusan block ini.

**Enforcement per platform**: memakai framework yang sama yang sudah dipilih untuk sensor jaringan pasif di bagian 3.2, diperluas dari observasi ke enforcement aktif. Linux lewat `aya` (eBPF hook di titik egress, konsisten dengan pilihan eBPF yang sudah ada, tanpa perlu dependency terpisah ke iptables/nftables), Windows lewat Windows Filtering Platform (sudah dipakai untuk observasi, diperluas untuk blocking), macOS lewat Network Extension framework (sama, `NEFilterDataProvider`/`NEFilterPacketProvider`). **Hook wajib dipasang di kedua family address (AF_INET dan AF_INET6)**: WFP punya layer terpisah untuk IPv4 dan IPv6 yang harus didaftarkan keduanya, eBPF di Linux perlu attach ke hook yang mencakup traffic IPv6 (bukan cuma filter berbasis IPv4 socket), macOS Network Extension juga wajib dikonfigurasi mencakup kedua stack. Kalau salah satu family tidak ter-cover, itu jadi bypass yang siap dieksploitasi, lihat suite regresi tambahan di `PRD.md` bagian 6.4.

### 3.9 Browser Extension Companion

Komponen resmi baru (keputusan produk, dicatat di `CHANGELOG.md`), ditambahkan untuk menutup gap yang tidak bisa dijangkau oleh monitoring level OS: GN-Shield di level `gn-shield-core` tidak punya visibilitas ke dalam konten/tab browser (halaman mana yang sedang dilihat, form apa yang diisi user, script apa yang jalan di dalam satu tab), lihat `docs/THREAT_MODEL.md` bagian 2.6 untuk detail ancaman yang ditutup.

**Prinsip desain paling penting: ini BUKAN alasan untuk melakukan TLS interception di level OS.** Ekstensi mendapat akses ke konten halaman lewat API resmi browser (content script, yang berjalan setelah browser sendiri men-decrypt HTTPS), bukan dengan memecah enkripsi dari luar. Ini mempertahankan model keamanan HTTPS standar dan tidak menambah GN-Shield sebagai titik yang bisa membaca semua traffic terenkripsi user, konsisten dengan posisi "bukan firewall/proxy TLS penuh" di `PRD.md` bagian 4.

**Komponen**:
- `gn-shield-browser-extension`: WebExtension, satu codebase yang kompatibel Manifest V3 (Chrome, Edge, Brave) dan WebExtensions API (Firefox). Ini proyek JS/TypeScript terpisah, TIDAK masuk workspace Cargo di bagian 2, disimpan di direktori terpisah (misal `browser-extension/`) dengan tooling dan proses build sendiri.
- `gn-shield-native-host`: binary Rust kecil yang jadi jembatan protokol native messaging (stdio, format yang diwajibkan Chrome/Firefox) ke IPC lokal yang sama dipakai `gn-shield-cli`. Browser men-spawn proses ini per koneksi (bukan proses permanen), jadi wajib startup sangat cepat dan ringan, murni bridge tanpa logic bisnis sendiri, semua keputusan tetap di `gn-shield-core`.

**Kemampuan yang didukung (dibatasi sengaja)**:
1. **Enforce domain blocklist di level page-load**, lewat `declarativeNetRequest` (Chrome MV3) atau `webRequest` blocking (Firefox). Blocklist yang dipakai SAMA dengan yang dikelola Update Service untuk DNS Filter (bagian 3.7), diambil sekali lewat native messaging saat startup dan disegarkan berkala, BUKAN query API eksternal per kunjungan halaman, supaya riwayat browsing tidak pernah terkirim ke pihak ketiga manapun. Ini lebih baik UX-nya dibanding blok di level DNS saja (yang kadang cuma bikin halaman "loading" lama tanpa pesan jelas).
2. **Heuristik form-action-mismatch untuk phishing**: content script ringan mengecek keberadaan input password di halaman dan apakah form submit ke origin berbeda dari halaman saat ini. WAJIB ada allowlist identity provider legitimate (Google, Microsoft, GitHub, Okta, Apple ID, dan penyedia OAuth/SSO umum lain) supaya flow login pihak ketiga yang normal tidak salah tangkap, ini perluasan dari prinsip Tier 4 domain allowlist di `docs/DECISION_ENGINE.md`, dikelola di daftar yang sama.
3. **Enforce blocklist domain/endpoint mining pool dikenal** (feed `coinblockerlists`, sama dengan yang dipakai DNS Filter dan IP Reputation Filter, satu sumber data konsisten lintas layer), mekanismenya sama dengan (1), untuk mitigasi in-page JavaScript/WASM cryptomining.

**Yang secara sadar TIDAK didukung** (supaya tidak overclaim ke user):
- **Deteksi ekstensi lain yang jahat**: browser mengisolasi ekstensi satu sama lain, WebExtension API tidak memberi visibilitas ke ekstensi lain yang terinstal. GN-Shield hanya bisa memindai file ekstensi di disk lewat static scan level OS (sudah dibahas di `docs/THREAT_MODEL.md` sebelumnya), bukan lewat ekstensi ini.
- **Deteksi in-page miner lewat profiling CPU per-tab**: API untuk ini tidak konsisten/tersedia luas lintas browser, dan kalaupun ada, sinyalnya tidak cukup reliable untuk dijadikan dasar blocking otomatis. Pendekatan yang dipakai murni blocklist domain/endpoint dikenal (poin 3 di atas), bukan behavior heuristic yang belum tentu akurat.
- **Analisis konten mendalam berbasis ML/NLP untuk deteksi phishing** (brand impersonation visual, dsb). Ini di luar scope karena berat secara komputasi dan butuh maintenance model yang signifikan, bertentangan dengan prinsip lightweight. Heuristik yang dipakai sengaja sederhana dan dapat dijelaskan (explainable), bukan black-box.

**Privasi**: ekstensi tidak pernah mengirim URL yang dikunjungi atau konten halaman ke server manapun. Semua pengecekan blocklist dilakukan terhadap data yang sudah di-cache lokal (didapat dari Update Service lewat `gn-shield-core`), sama seperti prinsip `telemetry_enabled = false` default di `docs/CONFIG_SCHEMA.md`. Kalau di masa depan dibutuhkan reputasi URL yang lebih granular dari sekadar domain, wajib pakai pendekatan privacy-preserving (misal hash-prefix matching ala Google Safe Browsing Update API, bukan mengirim URL penuh ke API eksternal per kunjungan), ini harus didesain eksplisit sebelum diimplementasikan, bukan ditambahkan diam-diam.

**Permission browser extension**: manifest wajib meminta permission seminimal mungkin. Untuk fitur enforce blocklist di semua navigasi, host permission yang luas memang secara inheren dibutuhkan (tidak terhindarkan untuk fitur ini), tapi harus dijelaskan eksplisit di privacy policy ekstensi saat submit ke web store, dan cakupan penggunaannya dibatasi hanya untuk pengecekan domain/heuristik yang didokumentasikan di sini, tidak lebih.

**Permission host manifest native messaging**: file manifest yang memberitahu browser lokasi binary `gn-shield-native-host` (`com.gnshield.host.json` untuk Chrome, lokasi setara untuk Firefox) WAJIB dikunci permission-nya sama ketatnya dengan file config/database di bagian 3.5 (hanya bisa ditulis oleh admin/root). Kalau file ini bisa ditimpa proses non-privileged, attacker lokal bisa mengarahkan browser untuk menjalankan binary jahat alih-alih `gn-shield-native-host` yang asli setiap kali ekstensi mencoba connect, ini jalur bypass yang serius kalau tidak dikunci sejak awal instalasi.

#### 3.9.1 Strategi Publish dan Review

**Developer mode/unpacked BUKAN jalur distribusi**: Chrome (sejak 2013-2014) hanya mengizinkan instalasi extension dari Chrome Web Store di channel stable/beta untuk consumer biasa, developer mode murni untuk testing dan browser akan menampilkan warning berulang/menonaktifkan extension yang di-load unpacked di luar sesi development. Firefox (sejak versi 43) mewajibkan semua extension ditandatangani Mozilla (AMO) di release channel, tidak bisa dimatikan kecuali pakai build khusus (Developer Edition/Nightly/ESR) yang tidak relevan untuk distribusi ke user umum.

**Teknik yang secara sengaja TIDAK dipakai**: force-install lewat enterprise policy (menulis policy Chrome/Firefox di registry/file lokal supaya extension otomatis terpasang tanpa klik user) secara teknis memungkinkan, tapi sengaja dihindari karena: (1) menampilkan banner "dikelola oleh organisasi Anda" di browser yang bisa terlihat mencurigakan bagi target pengguna GN-Shield yang sadar privasi, (2) ini persis teknik yang dipakai tool silent-install extension tanpa izin yang biasa dipakai adware/malware, memakainya akan merusak kredibilitas GN-Shield sebagai tool keamanan, dan (3) melanggar prinsip "user tetap pemegang keputusan akhir" di `README.md`.

**Jalur distribusi resmi**:
1. Publish ke Chrome Web Store (visibility "Unlisted" untuk instalasi lewat link langsung tanpa muncul di pencarian publik, atau "Public" kalau sudah siap ekspos luas) dan Firefox Add-ons (AMO), submit sebagai "Unlisted" untuk self-distribution tanpa listing publik kalau diinginkan, tetap wajib lewat proses signing Mozilla.
2. Installer `gn-shield-core` menampilkan link langsung ke listing store lewat CLI/notifikasi setelah instalasi daemon selesai, user klik "Add to Chrome/Firefox" sendiri. Ini satu klik yang disengaja, bukan otomatis, konsisten dengan prinsip consent eksplisit.
3. **Extension ID wajib di-fix sejak awal**: Chrome lewat field `key` di `manifest.json` (public key yang membuat ID deterministik lintas build), Firefox lewat `browser_specific_settings.gecko.id`. ID ini harus sudah ditentukan sebelum host manifest native messaging (yang berisi `allowed_origins`/`allowed_extensions`) di-bundle ke installer GN-Shield, karena host manifest butuh ID persis ini, tidak bisa "diisi belakangan".
4. **Submit lebih awal, bukan mepet deadline**: review submission pertama bisa memakan waktu bervariasi (permission seperti `nativeMessaging` dan host permission luas biasanya kena review lebih dalam), update ke listing yang sudah established biasanya lebih cepat. Strategi: submit versi MVP (cuma enforce blocklist) di awal Fase 4 (`ROADMAP.md`), bukan menunggu semua fitur selesai.
5. **Jaga permission stabil antar rilis**: menambah permission baru di update berikutnya bisa memicu review ulang yang lebih ketat, rencanakan kebutuhan permission di awal, hindari penambahan bertahap tiap rilis.

#### 3.9.2 Method Sync dengan gn-shield-core

Sengaja dirancang TIDAK bergantung pada koneksi yang harus tetap terbuka, karena service worker MV3 didesain berhenti sendiri setelah sekitar 30 detik idle, koneksi `connectNative` yang dibiarkan terbuka lama akan ikut terputus begitu itu terjadi. Semua komunikasi memakai `sendNativeMessage` (satu panggilan, request-response, bukan port persisten).

**Jalur 1, enforce blocklist (tanpa membangunkan JS tiap request)**: blocklist domain diterjemahkan jadi rule `declarativeNetRequest`, dimuat ke mesin filtering bawaan browser. Begitu rule termuat, browser menegakkan blocking secara native di level jaringan tanpa membangunkan service worker ekstensi per navigasi, ini krusial untuk resource footprint karena page load adalah titik yang paling sering terjadi. Sinkronisasi rule dipicu oleh `runtime.onStartup`/`onInstalled` dan `chrome.alarms` (timer periodik, selaras siklus refresh Update Service): tanya versi/hash blocklist ke `gn-shield-native-host`, bandingkan dengan yang tersimpan di `chrome.storage.local`, kalau beda ambil delta dan update lewat `declarativeNetRequest.updateDynamicRules()`.

**Jalur 2, heuristik real-time (form-action-mismatch)**: content script deteksi pola mencurigakan → kirim pesan ke background service worker lewat `runtime.sendMessage` (ini yang membangunkan worker kalau tidur) → background panggil `sendNativeMessage` sekali ke `gn-shield-native-host` → diteruskan ke `gn-shield-core`, masuk Decision Engine yang SAMA dengan yang dipakai untuk keputusan file/proses (Allow/Block/PromptUser di `docs/DECISION_ENGINE.md`) → hasil dikirim balik, ditampilkan sebagai banner peringatan di halaman dan/atau notifikasi OS yang sama, supaya UX konsisten di semua jenis deteksi → keputusan user tersimpan ke Tier 4 domain allowlist yang sama.

**`gn-shield-native-host`**: di-spawn browser per panggilan `sendNativeMessage`, murni menerjemahkan wire format native messaging (length-prefix 4 byte plus JSON UTF-8) ke IPC lokal yang sama dipakai `gn-shield-cli`, lalu keluar secepatnya. Tidak ada logic bisnis di komponen ini, semua keputusan tetap di `gn-shield-core`, satu sumber kebenaran. Target latency tetap mengikuti anggaran hot-path yang sama dengan keputusan lain (`PRD.md` bagian 6.3), supaya tidak menambah delay yang terasa saat page load atau saat form dicek.

**Kenapa bukan WebSocket untuk sinkronisasi ekstensi**: komunikasi ekstensi ke `gn-shield-core` ini murni IPC lokal di mesin yang sama (lewat `gn-shield-native-host`), bukan traffic jaringan, jadi tidak ada "traffic percuma" yang perlu dihemat di sini terlepas dari mekanisme apapun yang dipakai. Kalaupun WebSocket dipertimbangkan untuk menjaga service worker tetap hidup, sejak Chrome 116 caranya justru dengan mengirim pesan keepalive setiap sekitar 20 detik (karena timer idle 30 detik reset oleh aktivitas WebSocket), yang berarti traffic/wake-up JAUH LEBIH SERING dibanding desain `chrome.alarms` periodik yang sudah dipakai (tiap beberapa jam). WebSocket di titik ini akan lebih boros, bukan lebih hemat, jadi sengaja tidak dipakai. Isu traffic yang sebenarnya relevan ada di komunikasi `gn-shield-core` ke Update Service (bagian 3.6), bukan di jalur ini.

**Kebijakan kalau `gn-shield-native-host`/`gn-shield-core` tidak bisa dihubungi (fail-open, bukan fail-closed)**: ini pengecualian sadar dari prinsip fail-closed yang berlaku di komponen lain (`docs/CONFIG_SCHEMA.md` bagian 12). Kalau ekstensi gagal terhubung ke `gn-shield-core` (daemon belum jalan, belum terinstal, atau native messaging bermasalah), ekstensi TIDAK memblokir navigasi apapun (fail-open untuk enforcement page-load), cukup menampilkan indikator visual jelas (misal ikon toolbar berubah warna/status "GN-Shield tidak terhubung") supaya user sadar lapisan proteksi tambahan ini sedang tidak aktif. Alasan pengecualian ini: DNS Filter di level OS (bagian 3.7) tetap jalan independen dari status ekstensi, jadi proteksi dasar tidak sepenuhnya hilang, dan memblokir seluruh browsing karena satu komponen tambahan terputus adalah gangguan yang tidak proporsional dibanding manfaatnya, bertentangan dengan prinsip "tidak mengganggu aktivitas lain" di `README.md`. Implementasi wajib mengecek status koneksi ini secara berkala (bukan cuma sekali saat startup) supaya indikator tetap akurat kalau koneksi putus di tengah jalan.

## 4. Alur Data Contoh: Deteksi Ransomware

1. Sensor filesystem Linux (fanotify) mendeteksi banyak file dimodifikasi dalam window waktu singkat di direktori yang dipantau.
2. Event dikirim ke `gn-shield-core`, diteruskan ke Decision Engine.
3. Decision Engine cek: apakah path ini masuk exclusion list development (`node_modules`, `.git`, `target`)? Kalau ya, turunkan sensitivitas sesuai aturan di `docs/DECISION_ENGINE.md`, jangan langsung abaikan total.
4. Kalau bukan exclusion, cek entropy shift pada file yang dimodifikasi, dan cek apakah honeypot file ikut berubah.
5. Kalau confidence tinggi (honeypot berubah + entropy shift signifikan + kecepatan modifikasi di atas threshold), Decision Engine mengembalikan aksi Block, `gn-shield-core` menjalankan alur containment dulu (freeze proses, putus jaringan, blok write/unlink lebih lanjut, pantau child process baru dengan scope ketat ke bawah) sebelum benar-benar terminate, BUKAN langsung kill, lihat `docs/DECISION_ENGINE.md` bagian 9 untuk urutan lengkapnya. Setelah proses ter-contain dan dihentikan, lakukan quarantine file dan kunci direktori yang terdampak (kalau memungkinkan lewat filesystem snapshot, lihat `docs/THREAT_MODEL.md` bagian 2.2 soal batas cakupannya), baru memberi notifikasi ke user.
6. Kalau confidence menengah, kembalikan PromptUser, tunjukkan notifikasi non-blocking, tunggu keputusan user, simpan keputusan ke allowlist yang sesuai.

## 5. Justifikasi Pemilihan Teknologi Kunci

Dicatat di sini supaya keputusan ini tidak diubah tanpa sadar oleh kontributor baru atau AI agent, lihat juga `AGENTS.md` bagian larangan mengganti crate inti tanpa dokumentasi.

- **YARA-X, bukan yara-rust (binding C)**: pure Rust, dikembangkan resmi oleh VirusTotal, sudah dipakai produksi memindai miliaran file. Menghilangkan risiko memory-safety di FFI boundary yang ada di binding C.
- **rusqlite, bukan sled**: `sled` masih berstatus beta bertahun tahun tanpa progres jelas ke versi stabil 1.0, tidak cocok untuk data kritikal di tool keamanan.
- **aya untuk eBPF**: satu satunya opsi pure Rust yang matang untuk eBPF di Linux, meski API-nya masih menuju stabilisasi 1.0, jadi versi harus di-pin ketat di `Cargo.lock`. **Wajib memakai CO-RE (Compile Once, Run Everywhere) lewat dukungan BTF di `aya`**, bukan program eBPF yang di-compile spesifik untuk satu versi kernel. ini krusial khususnya untuk CachyOS yang rolling-release dengan kernel update rutin, tanpa CO-RE, program eBPF GN-Shield berisiko berhenti berfungsi (atau gagal load) setiap kali user update kernel lewat `pacman -Syu`, memaksa rebuild/rilis ulang GN-Shield setiap ada kernel baru, yang bertentangan dengan requirement reliable dan lightweight.
- **ferrisetw untuk ETW Windows**: pilihan paling relevan yang ada di ekosistem Rust untuk ETW, tapi statusnya masih "work in progress" menurut maintainer sendiri, jadi perlu wrapper internal yang membatasi permukaan API yang dipakai, supaya kalau ferrisetw berubah drastis, dampaknya lokal ke satu modul saja.
- **hickory-dns untuk DNS proxy**: matang, dipakai beberapa resolver production, tapi baru saja rebranding dari trust-dns, jadi cek dokumentasi versi terbaru saat implementasi, jangan berpatokan pada nama lama.
- **psl dan publicsuffix untuk komputasi eTLD+1 (dua lapis)**: `psl` di-compile langsung jadi kode native Rust dan disinkronkan otomatis dari publicsuffix.org lewat CI upstream, dipakai sebagai fallback yang selalu tersedia tanpa network. `publicsuffix` mem-parse list mentah di runtime, dipakai sebagai lapis dinamis yang disegarkan Update Service secara berkala, supaya freshness PSL tidak bergantung pada rebuild binary manual, lihat `docs/ARCHITECTURE.md` bagian 3.7 untuk desain lengkapnya. Dipilih dibanding menulis logic split-by-dot sendiri karena Public Suffix List berubah dari waktu ke waktu dan implementasi custom rawan bug bypass, lihat `docs/DECISION_ENGINE.md` Tier 4 untuk kasus konkret kenapa ini penting.
- **Native messaging, bukan TLS interception, untuk visibilitas browser**: dipilih supaya GN-Shield tidak perlu memecah enkripsi HTTPS di level OS untuk mendapat visibilitas konten halaman. Trade-off-nya adalah GN-Shield hanya bisa melihat apa yang browser sendiri sudah decrypt dan expose lewat content script API, bukan traffic mentah, tapi ini trade-off yang secara sadar diterima karena melakukan TLS interception sendiri akan menambah attack surface besar dan bertentangan dengan posisi GN-Shield sebagai bukan firewall/proxy penuh, lihat `docs/ARCHITECTURE.md` bagian 3.9.

Setiap keputusan di atas harus dicek ulang statusnya (rilis terbaru, advisory keamanan terbuka) sebelum benar benar dipakai di kode produksi, karena status crate bisa berubah setelah dokumen ini ditulis.

## 6. Keputusan Arsitektur Final & Keputusan Terbuka

### 6.1 Keputusan Final

- **Format IPC**: Ditetapkan menggunakan **Unix domain socket dengan JSON-RPC** (menggunakan `serde_json` dan framing newline/length-prefixed ringan) di Linux/macOS, serta Named Pipes di Windows. Opsi gRPC **secara sadar ditolak** karena overhead dependensinya (`tonic`, `prost`, HTTP/2 `h2`) akan membengkakkan binary size dan konsumsi RAM idle, bertentangan dengan prinsip *lightweight*.
- **Otorisasi IPC & Mutasi State**: Operasi baca status aman diakses proses user yang sama. Namun, operasi mutasi state (menambah allowlist permanen, mengubah konfigurasi, mematikan proteksi) **wajib memverifikasi hak akses administratif** (misal verifikasi `SO_PEERCRED` UID=0 / integrasi polkit / sudo di Linux) untuk mencegah malware lokal non-privileged menyuruh `gn-shield-core` meng-allowlist dirinya sendiri.
- **Migrasi Skema Database & Konfigurasi**: Menggunakan `PRAGMA user_version` SQLite dengan migrasi tertanam (embedded schema migrations) di dalam `gn-shield-storage`. Setiap perubahan skema tabel ditandai dengan versi inkremental monoton yang dieksekusi saat daemon startup sebelum koneksi dibuka ke komponen lain.

### 6.2 Keputusan Terbuka / Dalam Pemantauan

- Mekanisme quarantine file dan containment proses: sudah final, lihat `docs/DECISION_ENGINE.md` bagian 9 (Aksi Remediasi untuk Proses Berjalan).
- Batas operasional fanotify: pencegahan recursive deadlock dengan fast-path bypass untuk PID `gn-shield-core` sendiri dan watchdog timeout 100-250ms pada event blocking `FAN_OPEN_EXEC_PERM`.

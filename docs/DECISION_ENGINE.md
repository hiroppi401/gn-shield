# Decision Engine Specification

Dokumen ini adalah spesifikasi mengikat untuk komponen paling sensitif di GN-Shield: mesin yang memutuskan apakah sesuatu di-allow, di-block, atau ditanyakan ke user. Perubahan di sini berdampak langsung ke false positive rate dan ke risiko keamanan, jadi setiap perubahan harus melalui review eksplisit, lihat `AGENTS.md` bagian 4.

## 1. Tujuan Desain

Sistem scoring dibuat bertingkat (bukan biner block/allow) supaya bisa membedakan tingkat keyakinan, dan supaya keputusan user (allowlist) selalu bisa mengalahkan sinyal otomatis lain. Ini langsung menjawab kebutuhan dari `PRD.md` bagian 6.2: nol false positive out-of-the-box terhadap developer tools umum.

**Penting: ada tiga jalur keputusan yang berbeda, bukan satu, bukan dua.** Supaya tidak ambigu bagi siapapun yang mengimplementasikan (termasuk AI agent), dokumen ini secara eksplisit membedakan:

1. **Jalur scoring umum** (bagian 3 dan 4), dipakai untuk keputusan malware/supply-chain secara umum: menghasilkan `static_score`, `hash_reputation`, `behavior_score`, digabung lewat formula berbobot di `decide()`, dan bisa di-override oleh allowlist (Tier 1, 2, 3, 3b, 4).
2. **Jalur detektor ransomware** (dijelaskan di bagian 2 Tier 5, dan bagian 5 poin 2), yang SENGAJA TIDAK memakai formula berbobot yang sama. Ransomware butuh aturan eksplisit berbasis kondisi (honeypot berubah DAN entropy shift DAN kecepatan modifikasi di atas ambang, semuanya harus terpenuhi bersamaan), bukan rata-rata tertimbang, karena kalau sinyal ransomware yang sangat kuat (honeypot berubah) hanya jadi satu komponen dari skor rata-rata, sinyal kuat itu bisa "diencerkan" oleh komponen lain yang rendah, sehingga terlambat mem-block. Jalur ini punya pintu keluarnya sendiri ke Action::Block/PromptUser, terpisah dari `decide()` di bagian 4.
3. **Jalur network/IP reputation** (bagian 5 poin 4, `docs/ARCHITECTURE.md` bagian 3.8), lebih sederhana dari dua jalur di atas, murni lookup biner terhadap feed reputasi IP curated, tidak melalui formula scoring maupun kondisi kompleks. Beroperasi di level koneksi jaringan, bukan level file/proses, sehingga secara alami terpisah dari `decide()`. **Penting**: percobaan koneksi yang diblokir jalur ini tetap wajib dilaporkan balik sebagai input ke `behavior_score` milik proses yang mencobanya (bagian 3), supaya proses yang berulang kali mencoba (dengan IP berbeda-beda tiap kali) tidak bisa terus lolos tanpa pernah proses itu sendiri dievaluasi.

Implementasi wajib memisahkan ketiga jalur ini secara kode (fungsi/modul berbeda), bukan mencoba memaksakan sinyal ransomware atau IP reputation masuk sebagai salah satu input `behavior_score` yang diproses lewat formula berbobot bagian 4 secara langsung (meski hasil akhirnya, seperti disebut di poin 3, tetap dilaporkan balik sebagai salah satu KOMPONEN input, bukan menggantikan jalur keputusannya sendiri). Kalau nanti ditemukan cara yang lebih baik untuk menyatukan ketiganya, itu perubahan arsitektural yang harus didiskusikan eksplisit dulu, bukan keputusan implementasi diam diam, sesuai `AGENTS.md` bagian 4.

## 2. Lapisan Allowlist (Tier)

Diurutkan dari paling spesifik/kuat ke paling umum. Tier yang lebih tinggi selalu override tier di bawahnya. Ada satu mekanisme tambahan (Tier 3b) yang sifatnya sementara/kedaluwarsa, disisipkan di antara Tier 3 dan Tier 4 karena kekuatannya di antara keduanya, khusus untuk kasus binary yang hash-nya sengaja sering berubah.

**Catatan penting soal penomoran**: Tier 1 sampai 4 (plus 3b) adalah bagian dari satu stack yang sama, semuanya feed ke sinyal `allowlist_override` di jalur scoring umum (bagian 3). "Tier 5" yang disebutkan di bawah (exclusion direktori ransomware) BUKAN bagian dari stack override yang sama, ini disebut "Tier 5" murni karena alasan historis penomoran berurutan saat dokumen ini ditulis, bukan karena dia lebih lemah dari Tier 4 dalam hierarki yang sama. Tier 5 adalah parameter sensitivitas untuk jalur detektor ransomware yang terpisah (lihat bagian 1 di atas), tidak pernah dicek atau dipakai oleh fungsi `decide()` di bagian 4. Kalau ini membingungkan, anggap saja "Tier 5" sebagai nama lain dari "Ransomware Sensitivity Exception", bukan tier allowlist kelima dalam urutan yang sama dengan Tier 1-4.

### Tier 1: Hash Allowlist

Paling kuat, paling spesifik. Mengunci ke satu file persis lewat hash SHA-256 atau BLAKE3.

```toml
[[allowlist.hash]]
sha256 = "e3b0c44298fc1c149afbf4c8996fb..."
name = "cloudflared"
scope = ["network", "process", "filesystem"]
added_by = "user"          # atau "default_ruleset"
added_at = "2026-09-05T10:00:00Z"
```

Kalau hash file berubah (update aplikasi), entry ini otomatis tidak berlaku lagi untuk file baru, harus lewat Tier 2/3 atau prompt ulang, ini penting supaya update aplikasi yang disusupi malware tidak otomatis lolos.

### Tier 2: Publisher/Code-Signing Trust

Verifikasi lewat digital signature atau checksum package manager.

- Linux: verifikasi lewat package manager (`pacman -Qkk` untuk cek integritas file terinstal, atau checksum resmi dari repo AUR/official).
- Windows: verifikasi Authenticode signature, cocokkan nama publisher (misal "Cloudflare, Inc.", "Mozilla Corporation").
- macOS: `codesign --verify` dan cek Team ID developer.

```toml
[[allowlist.publisher]]
platform = "linux"
verified_by = "pacman"
package_name = "cloudflared"
auto_trust = true
```

### Tier 3: Path + Provenance

Untuk kasus di mana verifikasi publisher tidak tersedia (misal binary yang di-download manual atau dibangun sendiri dari source).

```toml
[[allowlist.path]]
path = "/usr/bin/cloudflared"
verified_by = "pacman"
auto_reverify_on_update = true
```

Field `auto_reverify_on_update` wajib true kalau `verified_by` bukan "manual", supaya begitu binary berubah (update), sistem otomatis re-cek, bukan asal percaya path lama selamanya.

### Tier 3b: Ephemeral Trust Cache untuk Direktori Build Output

Mekanisme terpisah dari Tier 1 sampai 4 (bukan Tier 5, lihat klarifikasi penomoran di bagian 2 di atas), dibuat khusus untuk kasus binary hasil build sendiri (`cargo build`, `npm run build`, dsb) yang hash-nya selalu berubah tiap kali dicompile ulang, sehingga tidak pernah bisa otomatis cocok dengan Tier 1 (hash allowlist permanen). Tanpa mekanisme ini, developer yang sering build-jalankan-build-jalankan akan terus menerus di-prompt untuk binary yang secara kode sebenarnya sama, cuma hash-nya beda tiap build.

**Cara kerja**: saat user menjawab "Always Allow" untuk binary yang terletak di direktori yang cocok dengan pola build output (`**/target/debug/**`, `**/target/release/**`, `**/dist/**`, `**/build/**`, atau pola custom lain yang dikonfigurasi), sistem TIDAK membuat entry Tier 1 permanen (karena hash akan berubah lagi di build berikutnya). Sebagai gantinya, sistem membuat entry cache sementara di tabel terpisah (bukan tabel allowlist permanen), dengan struktur:

```toml
# ini BUKAN entry statis di config.toml, melainkan representasi konseptual
# dari row yang dibuat runtime di storage (rusqlite), disertakan di sini
# supaya jelas strukturnya
[trust_cache_entry]
directory = "/home/user/project/target/debug"
filename = "myapp"
created_at = "2026-09-06T14:00:00Z"
expires_at = "2026-09-06T18:00:00Z"   # sliding, diperpanjang tiap dipakai
source_decision = "always_allow"
```

**Aturan kunci**:
1. Key cache adalah kombinasi **direktori DAN nama file**, bukan direktori saja. Kalau muncul file baru dengan nama berbeda di direktori yang sama, itu tetap memicu `PromptUser` baru, supaya cache tidak berubah jadi "percaya semua isi folder ini".
2. TTL default 4 jam (`build_directory_ttl_seconds` di config, lihat `docs/CONFIG_SCHEMA.md`), mendekati durasi sesi development aktif yang wajar. Setiap kali cache ini dipakai untuk meloloskan build baru, TTL diperpanjang lagi dari titik itu (sliding window), bukan TTL tetap sejak pertama dibuat.
3. Kalau tidak ada aktivitas build baru di direktori/file itu sampai TTL habis, cache dianggap kedaluwarsa. Build berikutnya di direktori itu akan memicu `PromptUser` dari awal, bukan otomatis lolos. Ini membatasi jendela risiko kalau direktori tersebut disusupi setelah user berhenti aktif development di sana.
4. Cache ini HANYA memengaruhi keputusan `PromptUser` vs `Allow`, tidak pernah membatalkan static scan (YARA-X, hash reputation) atau behavior monitoring. Kedua lapisan itu tetap berjalan penuh terhadap setiap binary baru, persis prinsip yang sama dengan pemisahan Tier 5 di atas. Kalau static scan atau hash reputation kebetulan menghasilkan sinyal `KnownBad` untuk binary baru (skenario sangat tidak mungkin untuk kode sendiri, tapi tetap dijaga), itu langsung auto-block, cache ini tidak bisa meng-override itu.
5. Setiap pemakaian cache (build baru yang lolos tanpa prompt karena cache ini) dicatat di audit log (`docs/DECISION_ENGINE.md` bagian 7), supaya tetap ada jejak yang bisa ditelusuri, bukan "menghilang" dari radar.
6. Direktori yang eligible untuk mekanisme ini secara default mengikuti pola yang sama dengan Tier 5 ransomware exclusion (`node_modules` dikecualikan dari daftar ini karena bukan direktori output build milik user sendiri, fokusnya `target/`, `dist/`, `build/`, `out/`), tapi user bisa menambah pola custom lewat config.

**Kenapa bukan Tier 3 biasa**: Tier 3 (Path + Provenance) mengasumsikan path stabil dengan `auto_reverify_on_update` sebagai mekanisme re-cek, cocok untuk binary yang jarang berubah (installed application). Untuk binary yang sengaja dan sering berubah (dev build loop), pendekatan re-verify saja tidak cukup karena akan re-trigger prompt tiap kali. Time-boxed cache ini secara sadar dipisah supaya kedua kasus (aplikasi stabil vs binary dev aktif) punya jalur berbeda dengan trade-off keamanan yang sesuai masing masing.

### Tier 4: Domain/Network Exception

Untuk kasus tunnel dan tools jaringan developer, supaya subdomain acak tidak dianggap pola DGA (Domain Generation Algorithm) malware.

```toml
[[network.domain_allowlist]]
pattern = "*.trycloudflare.com"
reason = "cloudflare_tunnel_official"

[[network.domain_allowlist]]
pattern = "*.cfargotunnel.com"
reason = "cloudflare_tunnel_official"

[[network.domain_allowlist]]
pattern = "*.ngrok.io"
reason = "ngrok_tunnel"

[[network.domain_allowlist]]
pattern = "*.ts.net"
reason = "tailscale"

[[network.ip_allowlist]]
cidr = "203.0.113.0/24"
reason = "override manual, IP ter-flag reputasi tapi terverifikasi legitimate"

[[network.ip_allowlist]]
cidr = "2001:db8::/32"
reason = "contoh entry IPv6, format sama dengan IPv4, wajib didukung sama lengkapnya"
```

Daftar default ini dikirim bersama instalasi awal GN-Shield (lihat bagian 6), bukan sesuatu yang harus user tambahkan manual sejak hari pertama.

**Cara matching wajib berbasis eTLD+1 yang dihitung lewat Public Suffix List (PSL), bukan string suffix naif.** Pattern seperti `*.trycloudflare.com` harus dicocokkan dengan memecah hostname menjadi label (dipisah titik) dan membandingkan tepat pada batas label, bukan sekadar `hostname.ends_with(".trycloudflare.com")` pada level string mentah. Perbedaan ini penting karena string matching naif rentan terhadap domain yang sengaja dibuat mirip (misal domain attacker yang confusingly menyertakan `trycloudflare.com` sebagai bagian nama tanpa jadi eTLD+1 yang sebenarnya). Implementasi PSL memakai dua lapis (compiled-in `psl` sebagai fallback, `publicsuffix` untuk parsing list yang disegarkan Update Service di runtime), lihat `docs/ARCHITECTURE.md` bagian 3.7 untuk desain lengkapnya, supaya freshness PSL tidak bergantung pada rebuild binary manual.

**Peringatan penting soal warisan trust**: entry di Tier 4 memberi exception HANYA untuk domain persis yang disebutkan (eTLD+1-nya), tidak untuk domain lain yang kebetulan juga terdaftar sebagai private suffix di PSL. Status "terdaftar di PSL" (artinya pihak ketiga bisa mendaftar subdomain di sana) bukan indikator trust, itu murni penanda teknis soal di mana batas kepemilikan domain terpecah. Jangan pernah membuat logic yang otomatis mempercayai semua domain yang statusnya "private suffix di PSL", karena banyak platform hosting gratis (blog, page builder, dsb) juga berstatus private suffix di PSL dan justru sering disalahgunakan untuk hosting phishing.

Domain age check (newly registered domain, lihat `docs/THREAT_MODEL.md` bagian 2.3) dan typosquatting comparison juga wajib dihitung di level eTLD+1 hasil PSL, bukan raw hostname, karena data registrasi WHOIS/RDAP memang tercatat di level itu.

### Tier 5: Context-Aware Directory Exception

Untuk menghindari false positive ransomware detector terhadap build tool dan package manager.

```toml
[[ransomware.excluded_paths]]
path_pattern = "**/node_modules/**"
reason = "development_workflow"
sensitivity = "reduced"   # bukan "disabled", lihat catatan di bawah

[[ransomware.excluded_paths]]
path_pattern = "**/.git/**"
reason = "development_workflow"
sensitivity = "reduced"

[[ransomware.excluded_paths]]
path_pattern = "**/target/**"
reason = "rust_build_artifacts"
sensitivity = "reduced"
```

Catatan penting: `sensitivity = "reduced"`, bukan "disabled". Direktori ini tetap dipantau, hanya dengan threshold yang lebih longgar. Alasan: mass file write yang benar benar berasal dari ransomware sungguhan (yang kebetulan menyasar direktori ini) tetap harus punya jalur terdeteksi, walau probabilitasnya kecil. Jangan ubah field ini menjadi exclusion total tanpa diskusi eksplisit, karena ini melemahkan proteksi inti ransomware.

### Batas Cakupan Tier 5 (Wajib Dipahami Sebelum Implementasi)

Ini bagian yang paling sering disalahpahami, jadi ditulis eksplisit supaya tidak ambigu untuk siapapun yang membaca, termasuk AI agent.

`[[ransomware.excluded_paths]]` HANYA mengurangi sensitivitas satu detektor spesifik: pola ransomware (mass file modification dalam window waktu singkat, dikombinasikan dengan entropy shift dan honeypot check). Entry di tier ini **tidak** dan **tidak boleh** memengaruhi dua lapisan deteksi berikut, yang harus tetap berjalan penuh terlepas dari path apapun:

1. **Static malware scanning (YARA-X + hash reputation)**. Setiap file baru yang ditulis ke disk, termasuk di dalam `node_modules`, `.git`, atau `target`, tetap wajib melalui on-access scan yang sama seperti file di direktori lain. Package manager (npm, cargo, pip) adalah vektor supply chain attack yang nyata, lihat `docs/THREAT_MODEL.md` bagian 2.5, jadi mengecualikan direktori ini dari static scan sama sekali akan menciptakan blind spot yang serius.
2. **Process behavior monitoring (eBPF/ETW/EndpointSecurity)**. Apa yang dilakukan proses (network call, akses ke `~/.ssh` atau kredensial lain, spawn shell, download binary tambahan) tetap dipantau, tidak peduli proses itu dipicu oleh script di dalam `node_modules` atau bukan. Ini penting khususnya untuk malicious postinstall/prepare script npm, yang sering jadi titik eksekusi pertama malware supply chain.

Implementasi wajib memisahkan secara arsitektural antara "ransomware behavioral detector" (yang boleh punya exclusion path) dengan "static scanner" dan "process behavior monitor" (yang tidak boleh punya exclusion path berbasis direktori sama sekali, hanya boleh punya exclusion berbasis Tier 1 sampai 3 allowlist yang mengunci ke identitas file/publisher spesifik, bukan ke lokasi folder).

Kalau implementasi ternyata menyatukan ketiga detektor ini di satu jalur kode yang sama sehingga satu exclusion path memengaruhi semuanya sekaligus, itu adalah bug arsitektur yang harus diperbaiki sebelum rilis, bukan trade-off yang diterima.

**Wajib resolve symlink sebelum matching pattern exclusion**: path yang dicek terhadap pola exclusion (`node_modules`, `.git`, `target`, dsb) wajib di-resolve dulu ke canonical path (symlink diikuti sampai target aslinya), bukan dicocokkan terhadap path mentah apa adanya. Tanpa ini, attacker bisa taruh symlink di dalam direktori yang di-exclude (misal `node_modules/innocent -> /home/user/Documents`) supaya direktori sensitif di luar situ ikut kebagian sensitivity rendah dari detektor ransomware, ini scope escape yang harus ditutup di level resolusi path, bukan dibiarkan sebagai asumsi implisit.

## 3. Sinyal yang Masuk ke Scoring

- `static_score`, hasil dari pattern matching YARA-X dan heuristik entropy/struktur binary. Rentang 0.0 sampai 1.0. **Termasuk argumen command-line proses** (diperlakukan sebagai teks yang ikut discan YARA-X, bukan cuma isi file), untuk menangkap pola LOLBins/one-liner fileless, lihat `docs/THREAT_MODEL.md` bagian 2.7.
- `hash_reputation`, hasil cek terhadap database malware dikenal (bukan allowlist, ini kebalikannya, mendeteksi hash yang memang jahat). Rentang 0.0 sampai 1.0.
- `behavior_score`, hasil dari monitoring eBPF/ETW/EndpointSecurity terhadap pola perilaku (mass file write, koneksi ke domain reputasi buruk, fan-out proses tidak wajar bagian 10, **indikator process injection** seperti `CreateRemoteThread`/`WriteProcessMemory` ke proses lain di Windows atau `ptrace` mencurigakan di Linux, lihat `docs/THREAT_MODEL.md` bagian 2.7, **percobaan koneksi yang diblokir IP Reputation Filter** (`docs/ARCHITECTURE.md` bagian 3.8), dilaporkan balik sebagai sinyal untuk proses yang mencobanya, bukan cuma diblokir di level koneksi lalu dilupakan, dsb). Rentang 0.0 sampai 1.0.

**Sinyal cryptomining tersembunyi (miner yang menghindari blocklist domain/IP standar)**: CPU tinggi berkelanjutan (misal di atas ambang tertentu selama beberapa menit terus-menerus) dari proses yang TIDAK ada di allowlist hash/publisher, DIKOMBINASIKAN dengan pola koneksi mirip protokol Stratum (`stratum+tcp://`, `stratum+ssl://`) atau koneksi persisten ke port non-standar yang tidak cocok pola traffic normal. **CPU tinggi sendirian, tanpa sinyal lain, WAJIB diberi bobot rendah dan tidak boleh cukup untuk memicu aksi apapun**, supaya beban kerja compute berat legitimate (render, training ML, compile besar) tidak salah tangkap. Sinyal ini hanya jadi signifikan kalau dikombinasikan dengan minimal satu sinyal lain (koneksi mencurigakan, proses tanpa hash reputation dikenal, dsb), konsisten dengan formula berbobot di bagian 4 yang memang mensyaratkan kombinasi sinyal untuk melewati threshold.
- `allowlist_override`, hasil lookup terhadap tier allowlist (Tier 1 sampai 4, termasuk Tier 3b sebagai cache sementara). Kalau ada match di tier manapun (termasuk cache yang masih dalam TTL), ini langsung dipakai, sinyal lain diabaikan untuk keputusan (tapi tetap dicatat di log untuk audit). Urutan lookup: Tier 1 (hash) dan reputasi malware dicek lebih dulu tanpa syarat (supaya `KnownBad` selalu bisa override apapun), baru kemudian Tier 2/3/3b/4 untuk menentukan `Trusted`.

**Penting, arah nilai ketiga sinyal numerik (wajib konsisten, sering disalahpahami)**: `static_score`, `hash_reputation`, dan `behavior_score` SEMUANYA searah "makin tinggi makin mencurigakan/jahat", 0.0 berarti bersih/tidak ada indikasi/tidak dikenal, 1.0 berarti indikasi ancaman maksimal. Tidak ada satupun dari ketiganya yang berarti "makin tinggi makin dipercaya", arah itu HANYA ada di `allowlist_override = TrustLevel::Trusted`, jalur yang sepenuhnya terpisah dari scoring numerik. Konsekuensinya: `hash_reputation` yang bernilai pecahan (misal 0.85, fuzzy/partial match yang belum cukup exact untuk jadi `KnownBad`) tetap sinyal MENCURIGAKAN, bukan sinyal "cukup dipercaya", dan wajib dilindungi ceiling/veto gate yang sama seperti `static_score` di bagian 4 (keduanya berbobot sama, 0.4), supaya tidak "terlarut" jadi Allow kalau sinyal lain kebetulan 0.0. Implementasi yang menafsirkan `hash_reputation` tinggi sebagai "boleh di-auto-allow" adalah kesalahan arah yang serius dan harus segera diperbaiki kalau ditemukan.

## 4. Formula dan Threshold (Baseline, Bisa Disetel Lewat Config)

```rust
struct Verdict {
    static_score: f32,
    hash_reputation: f32,
    behavior_score: f32,
    allowlist_override: Option<TrustLevel>,
}

fn decide(v: &Verdict) -> Action {
    if let Some(TrustLevel::Trusted) = v.allowlist_override {
        return Action::Allow; // short circuit, mengalahkan semua sinyal lain
    }
    if let Some(TrustLevel::KnownBad) = v.allowlist_override {
        return Action::Block; // untuk hash yang sudah dikonfirmasi malware, misal dari komunitas/database publik
    }

    // Ceiling / Veto Gates: Sinyal individual ekstrem tidak boleh diencerkan oleh sinyal lain yang bernilai 0.0
    if v.behavior_score >= 0.9 {
        return Action::Block; // Perilaku sangat berbahaya (misal: process injection terkonfirmasi, credential dumping)
    }
    if v.behavior_score >= 0.7 || v.static_score >= 0.8 || v.hash_reputation >= 0.8 {
        return Action::PromptUser; // Sinyal statis, behavioral, atau hash-reputation kuat wajib ditinjau, tidak boleh jatuh ke Allow
    }

    let total = v.static_score * 0.4
        + v.hash_reputation * 0.4
        + v.behavior_score * 0.2;

    match total {
        t if t > 0.8 => Action::Block,
        t if t > 0.4 => Action::PromptUser,
        _ => Action::Allow,
    }
}
```

Bobot (0.4, 0.4, 0.2) dan threshold (0.8, 0.4) adalah baseline awal, dengan Ceiling/Veto Gate aktif untuk mencegah pengenceran (dilution) sinyal tunggal yang kuat. Nilai ini harus disetel ulang berdasarkan hasil pengujian terhadap suite regresi false positive (`PRD.md` bagian 6.4) dan sampel malware nyata sebelum rilis publik. Catat perubahan nilai ini di `CHANGELOG.md` beserta alasan dan hasil pengujian yang mendasarinya.

## 5. Kategori Confidence Tinggi yang Boleh Auto-Block

Sesuai `AGENTS.md` bagian 1 poin 3, auto-action (block/kill process) tanpa menunggu konfirmasi user HANYA boleh untuk kasus berikut. Menambah kategori baru ke daftar ini butuh update dokumen ini secara eksplisit, bukan keputusan implementasi diam diam:

1. Hash file cocok persis dengan database malware yang sudah terverifikasi dari sumber terpercaya (misal MalwareBazaar dengan confidence tinggi), DAN file tersebut tidak ada di allowlist tier manapun.
2. Pola ransomware dengan SEMUA kondisi berikut terpenuhi bersamaan: honeypot file berubah, entropy shift signifikan pada banyak file dalam window waktu singkat, DAN path yang terdampak bukan bagian dari exclusion Tier 5 dengan sensitivity reduced yang masih dalam threshold longgarnya.
3. Proses yang terverifikasi menjalankan known exploit tool (bukan sekadar mirip pola, tapi match signature spesifik) terhadap proses sistem kritikal.
4. Koneksi jaringan ke IP address yang terkonfirmasi ada di feed reputasi malware/C2 curated (`docs/ARCHITECTURE.md` bagian 3.8), DAN IP tersebut tidak ada di `network.ip_allowlist`. Auto-block di sini murni di level koneksi (drop paket/tolak koneksi), bukan mematikan proses yang mencoba melakukannya, supaya tetap konsisten dengan cakupan sempit yang didefinisikan di bagian 3.8 (bukan firewall per-proses penuh).
5. **Proses yang berulang kali mencoba konek ke IP yang diblokir IP Reputation Filter** (baseline: 3 kali percobaan berbeda dalam window 5 menit, dikonfigurasi lewat `docs/CONFIG_SCHEMA.md`), terlepas dari apakah masing-masing percobaan individual pakai IP yang berbeda-beda. Ini menutup celah di mana proses jahat bisa terus mencoba IP C2 alternatif satu-satu (masing-masing diblokir sendiri-sendiri di level koneksi poin 4) tanpa pernah proses itu SENDIRI dievaluasi/di-contain. Begitu ambang ini terlampaui, proses masuk alur containment penuh di bagian 9, bukan cuma koneksinya yang diblokir lagi.

Di luar tiga kasus ini, aksi default adalah PromptUser, tidak boleh Block otomatis.

## 6. Default Ruleset Saat Instalasi (Learning Mode)

Saat instalasi pertama, GN-Shield melakukan:

1. Scan daftar package terinstal lewat package manager sistem.
2. Cocokkan dengan daftar known developer tools bawaan (termasuk namun tidak terbatas pada: cloudflared, ngrok, Tailscale, Docker, Podman, git, node/npm, cargo/rustup, python/pip, browser umum seperti Firefox dan Chromium).
3. Untuk setiap match, buat entry Tier 2 (Publisher/Code-Signing Trust) otomatis kalau verifikasi checksum package manager berhasil.
4. Tampilkan ringkasan ke user untuk approve secara batch (satu klik/konfirmasi untuk semua), bukan satu per satu.

Daftar known developer tools bawaan ini harus disimpan sebagai data terpisah (`default-allowlist.toml` atau setara) yang bisa diupdate lewat Update Service, supaya penambahan tools baru tidak butuh rilis ulang seluruh aplikasi.

## 7. Audit Log

Setiap keputusan (Allow, Block, PromptUser beserta jawaban user) harus dicatat dengan:

- Timestamp
- Identitas subjek (hash file, path, nama proses, atau domain)
- Semua nilai sinyal yang masuk ke scoring (`static_score`, `hash_reputation`, `behavior_score`, `allowlist_override`)
- Aksi akhir yang diambil
- Alasan dalam bahasa manusia, bukan cuma angka (contoh: "Diblokir karena honeypot file berubah dan entropy shift terdeteksi pada 340 file dalam 4 detik")

Log ini harus bisa diakses lewat `gn-shield-cli` dan dipakai sebagai bahan investigasi kalau user melaporkan false positive, supaya penyebabnya bisa ditelusuri dan dijadikan test case regresi baru.

## 8. Proses Menambah Aturan Allowlist Default Baru

1. Identifikasi tool yang sering menyebabkan false positive (dari laporan user atau pengujian internal).
2. Verifikasi tool tersebut memang legitimate dan pola perilakunya konsisten (misal selalu pakai domain pattern yang sama).
3. Tambahkan entry ke tier yang sesuai di `default-allowlist.toml`.
4. Tambahkan skenario tool tersebut ke suite regresi false positive (`PRD.md` bagian 6.4).
5. Dokumentasikan alasan penambahan di `CHANGELOG.md`.

## 9. Aksi Remediasi untuk Proses Berjalan (Incident Response)

Bagian 5 mendefinisikan KAPAN status `Block` diberikan untuk kasus confidence tinggi, bagian ini mendefinisikan APA YANG SEBENARNYA TERJADI secara operasional saat status itu berlaku pada proses yang SUDAH BERJALAN (bukan dicegah sebelum eksekusi lewat fanotify permission mode di `docs/ARCHITECTURE.md` bagian 3.4.1). Skenario ini muncul kalau: signature/hash reputation di-update lewat Update Service setelah proses sudah start, verdict scan file besar di background baru selesai setelah proses sempat jalan, atau residual TOCTOU risk di Windows yang sudah diakui di `docs/ARCHITECTURE.md` bagian 3.4.1.

**Prinsip inti: contain dulu, baru terminate, bukan langsung kill.** Beberapa malware (ransomware canggih, worm) punya dead man's switch, entah lewat companion/watchdog process terpisah yang memantau proses utama, atau logic internal yang memicu aksi destruktif tambahan kalau proses merasa diserang. Membunuh proses secara langsung tanpa containment dulu tidak menutup risiko ini. Urutan wajib:

**Tahap 1, Containment (sebelum terminate apapun)**:
1. **Freeze, bukan kill**: kirim `SIGSTOP` (Linux) atau mekanisme suspend setara (`NtSuspendProcess`/Job Object di Windows, EndpointSecurity di macOS). Ini murni dihentikan lewat scheduler kernel, proses tidak diberi kesempatan bereaksi lewat kodenya sendiri, beda dengan sinyal seperti `SIGTERM` yang bisa dipakai malware untuk trigger self-destruct routine.
2. **Putus akses jaringan proses itu SAJA**: perluasan target dari IP Reputation Filter (`docs/ARCHITECTURE.md` bagian 3.8), kali ini semua koneksi PID yang di-flag diputus, bukan cuma koneksi ke IP jahat dikenal, supaya proses tidak bisa exfiltrate atau memanggil bantuan C2 selama masih hidup dalam status beku.
3. **Blok write/delete lebih lanjut dari PID itu**: perluasan dinamis dari mekanisme fanotify permission (`docs/ARCHITECTURE.md` bagian 3.4.1), kali ini menyasar PID spesifik untuk event write/unlink, bukan cuma event Exec secara global. Mencegah kerusakan lanjutan (enkripsi/hapus file baru) meski proses sempat bisa jalan lagi.
4. **Pantau child process baru SELAMA jendela containment, scope KETAT ke bawah saja**: hanya descendant dari PID yang di-flag, TIDAK PERNAH ke atas (parent) atau ke samping (sibling). Kalau proses yang di-flag spawn child baru selama fase ini (baik sebagai reaksi containment atau memang sudah terjadwal), child itu otomatis ikut di-contain dengan langkah yang sama. Scoping ketat ke bawah ini krusial supaya tidak ikut mengontain seluruh proses induk yang legitimate (misal seluruh Firefox atau seluruh Docker daemon) hanya karena satu child/grandchild-nya yang kena flag.
5. **Jendela observasi singkat** (`containment_observation_window_ms` di config, baseline beberapa ratus milidetik), memberi waktu untuk containment child process baru (poin 4) selesai sebelum lanjut ke tahap berikutnya.

**Tahap 2, Terminate (setelah containment selesai)**:
6. Hentikan seluruh process tree yang sudah ter-contain (PID awal plus semua descendant yang ikut ter-contain di poin 4).
7. Quarantine file: pindahkan ke lokasi karantina, rename dengan ekstensi aman, cabut bit executable. Simpan metadata asli (path, timestamp, hash, alasan) supaya bisa direstore lewat `gn-shield-cli` kalau ternyata false positive. Ini konsisten dengan prinsip reversibilitas di `AGENTS.md` bagian 1 poin 3.
8. **Kasus file sudah dihapus sendiri (self-delete evasion)**: kalau file di disk sudah tidak ada saat proses terdeteksi, quarantine otomatis turun jadi cukup menghentikan proses. Dicatat di audit log sebagai sinyal tersendiri yang bisa memengaruhi scoring proses terkait.
9. **Notifikasi setelah tindakan**: sesuai kategori confidence tinggi, tidak menunggu konfirmasi user dulu, tapi user tetap diberi tahu segera sesudahnya (proses apa yang di-contain lalu dihentikan, file mana yang dikarantina), lihat `PRD.md` bagian 7.2.

**Pengaman wajib (safety guard), bukan opsional**:

- **Cek flag critical process sebelum terminate (Windows)**: Windows menandai sejumlah proses sebagai "critical process" di level kernel, memanggil `TerminateProcess` terhadap proses semacam ini menyebabkan seluruh sistem bugcheck (BSOD), bukan cuma proses itu yang mati. Implementasi WAJIB mengecek flag ini dulu sebelum eksekusi terminate, meski secara teori hash malware seharusnya tidak pernah cocok dengan proses sistem asli, ini pengaman lapis kedua terhadap kemungkinan false match yang tidak terduga.
- **Circuit breaker untuk mass-kill**: kalau lebih dari ambang tertentu (baseline: 5 proses) ter-auto-terminate dalam window waktu singkat (baseline: 60 detik), sistem WAJIB berhenti melanjutkan aksi auto-kill lebih lanjut dan masuk mode aman (cuma log dan notifikasi, minta konfirmasi manual untuk tindakan berikutnya). Alasan: lonjakan deteksi confidence tinggi di banyak proses berbeda dalam waktu singkat jauh lebih mungkin disebabkan data hash reputation yang buruk (dari update yang bermasalah) daripada infeksi multi-proses sungguhan, dan melanjutkan auto-kill tanpa jeda dalam situasi itu berisiko membuat GN-Shield sendiri jadi penyebab kerusakan/downtime ke sistem user, bertentangan langsung dengan prinsip "diam lebih baik daripada salah" di `README.md`. Ambang ini dikonfigurasi (`docs/CONFIG_SCHEMA.md`), bukan hardcoded.

## 10. Fan-Out Proses (Mass Child Spawning) Sebagai Sinyal, dan Allowlist untuk App Multi-Proses Legitimate

Jumlah child process yang di-spawn dalam waktu singkat ditambahkan sebagai salah satu input `behavior_score` (bagian 3), berguna untuk deteksi pola worm/self-propagating malware atau fork-bomb-style yang mencoba menyebar cepat. Sinyal ini terpisah dari mekanisme containment di bagian 9 (yang memantau child spawning HANYA dari proses yang sudah di-flag), di sini konteksnya deteksi awal untuk proses yang BELUM tentu jahat.

**Masalahnya**: banyak aplikasi legitimate memang secara wajar spawn banyak child process, browser (satu proses per tab/extension di Chromium), Docker/Podman/containerd (satu proses per container), build tool paralel (`make -j`, `cargo build` dengan banyak codegen unit). Tanpa pengecualian, sinyal ini akan salah tangkap aplikasi-aplikasi itu.

**Solusi, perluasan Tier 2/3 allowlist**: tambahkan flag `high_fanout_expected = true` pada entry allowlist untuk aplikasi yang memang dikenal multi-proses.

```toml
[[allowlist.publisher]]
platform = "linux"
verified_by = "pacman"
package_name = "firefox"
auto_trust = true
high_fanout_expected = true

[[allowlist.publisher]]
platform = "linux"
verified_by = "pacman"
package_name = "docker"
auto_trust = true
high_fanout_expected = true
```

**Batas penting supaya tidak jadi celah bypass**: flag ini HANYA meredam satu sinyal spesifik (jumlah child process) untuk komputasi `behavior_score` proses ANAK yang lineage-nya berasal dari proses trusted ini. Flag ini TIDAK meng-exempt child process dari pengecekan lain apapun (static scan, hash reputation, sinyal behavior lain seperti network/file access mencurigakan). Kalau ada child process yang memang jahat (misal ekstensi browser disusupi, atau container berisi malware), dia tetap terdeteksi lewat sinyalnya sendiri, cuma tidak otomatis ikut dicurigai semata-mata karena "induknya banyak anak". Default list untuk browser umum dan container runtime dikirim sebagai bagian dari `default-allowlist.toml` (bagian 6), diupdate lewat Update Service seperti aturan default lain, bukan sesuatu yang user harus tambahkan manual sejak hari pertama.

## 11. Pengelompokan (Batching) Notifikasi Ambigu (PromptUser)

### 11.1 Masalah Alert Fatigue pada Sesi Aktivitas Terkait
Saat pengguna melakukan instalasi tool baru atau menjalankan workflow kompleks (misal running development pipeline lokal yang memicu beberapa proses anak atau permintaan domain baru sekaligus), serangkaian event ambigu berkategori `PromptUser` dapat muncul dalam rentang waktu yang sangat rapat. Menampilkan popup terpisah untuk setiap event memicu alert fatigue hebat dan mendorong pengguna mengabaikan atau menyetujui semuanya secara membabi-buta.

### 11.2 Kriteria dan Mekanisme Pengelompokan
Pengelompokan notifikasi diatur melalui konfigurasi `[notifications]` dengan aturan deterministik:

1. **Jendela Waktu (Sliding Batch Window)**:
   Default bernilai `1000` milidetik (`batch_window_ms = 1000`). Setiap event `PromptUser` yang masuk menginisiasi atau memperpanjang timer pengumpulan selama window aktif.
2. **Kunci Pengelompokan (Grouping Key)**:
   Event dikelompokkan berdasarkan relasi proses induk: `parent_pid` (atau `parent_name` / `session_id`). Jika parent PID sama atau tergolong dalam tree instalasi yang sama, seluruh item diagregasikan ke dalam satu batch descriptor.
3. **Ambang Pengelompokan (Batch Threshold)**:
   Jika dalam jendela waktu terkumpul event sejumlah `>= batch_threshold_count` (default 2), sistem tidak memancarkan notifikasi individual, melainkan menggabungkannya ke dalam notifikasi ringkasan tunggal. Jika hanya ada 1 event hingga jendela waktu berakhir, notifikasi dipancarkan sebagai notifikasi tunggal biasa.

### 11.3 Format Notifikasi Ringkasan dan Aksi Pengguna
Notifikasi ringkasan menyajikan daftar ringkas dari event yang tertahan:
- **Judul**: `GN-Shield: {N} Aktivitas Baru Membutuhkan Izin`
- **Isi**: `Proses '{parent_name}' (PID {parent_pid}) memicu aktivitas:\n- {target_1}\n- {target_2} ...`
- **Aksi Tersedia**:
  - `Allow All Once`: Mengizinkan seluruh target dalam batch untuk eksekusi saat ini secara temporer.
  - `Always Allow All`: Menambahkan seluruh target dalam batch ke dynamic allowlist.
  - `Block All`: Memblokir seluruh target dalam batch secara aman.
  - `Review Individually`: Membuka tampilan detail per-item di `gn-shield-cli review`.

### 11.4 Penanganan Timeout (Safety Guard)
Jika dialog notifikasi batch tidak direspons oleh pengguna dalam `prompt_timeout_seconds` (default 60 detik), sistem menerapkan `default_action_on_timeout` (default `allow_once`). Sesuai prinsip reversibilitas pada `AGENTS.md` bagian 1 poin 3, sistem dilarang keras menerapkan auto-block permanen pada kondisi timeout ambigu.

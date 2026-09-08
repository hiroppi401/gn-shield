# Config Schema Reference

Vigil dikonfigurasi lewat file TOML. Dokumen ini adalah referensi skema lengkap. Kalau menambah field baru ke konfigurasi, update dokumen ini di pull request yang sama, jangan terpisah.

## 1. Lokasi File Config

- Linux: `/etc/vigil/config.toml` (sistem wide), `$XDG_CONFIG_HOME/vigil/config.toml` (per user, override sistem wide)
- Windows: `%PROGRAMDATA%\Vigil\config.toml`
- macOS: `/Library/Application Support/Vigil/config.toml`

Config per user selalu override config sistem wide untuk field yang sama, kecuali field yang eksplisit ditandai `locked = true` oleh admin (lihat bagian 13).

## 2. Struktur Top Level

```toml
[general]
log_level = "info"            # trace, debug, info, warn, error
telemetry_enabled = false       # default harus false, opt-in eksplisit
update_channel = "stable"       # stable, beta

[resource_limits]
max_cpu_percent_idle = 1.0
max_memory_mb_idle = 100
scan_queue_max_concurrent = "auto"     # "auto" = max(1, jumlah_core / 4), atau angka tetap untuk override manual
scan_priority = "low"                  # low, normal. "low" memetakan ke nice/ionice rendah (Linux), Below Normal (Windows), background QoS (macOS)
max_scan_file_size_mb = 200            # file di atas ini discan via mmap/background queue, bukan blocking on-access
adaptive_backoff_on_high_load = true   # kurangi concurrency otomatis kalau load rata rata sistem sedang tinggi

[incident_response]
mass_kill_circuit_breaker_count = 5        # ambang jumlah auto-terminate dalam window sebelum masuk mode aman
mass_kill_circuit_breaker_window_seconds = 60
quarantine_directory = "default"           # lokasi karantina, "default" = subfolder di storage path OS
freeze_before_kill = true                  # wajib true, containment (SIGSTOP/suspend) sebelum terminate, lihat DECISION_ENGINE.md bagian 9
network_isolate_before_kill = true         # putus semua koneksi PID yang di-flag sebelum terminate
filesystem_block_before_kill = true        # blok write/unlink lebih lanjut dari PID yang di-flag sebelum terminate
containment_observation_window_ms = 500    # jendela observasi child process baru selama containment

[[allowlist.hash]]
# lihat docs/DECISION_ENGINE.md bagian 2 Tier 1

[[allowlist.publisher]]
# lihat docs/DECISION_ENGINE.md bagian 2 Tier 2

[[allowlist.path]]
# lihat docs/DECISION_ENGINE.md bagian 2 Tier 3

[[network.domain_allowlist]]
# lihat docs/DECISION_ENGINE.md bagian 2 Tier 4

[[ransomware.excluded_paths]]
# lihat docs/DECISION_ENGINE.md bagian 2 Tier 5

[scoring]
weight_static = 0.4
weight_hash_reputation = 0.4
weight_behavior = 0.2
threshold_block = 0.8
threshold_prompt = 0.4

[dns_filter]
enabled = true
listen_address = "127.0.0.1:53"
upstream = ["1.1.1.1", "9.9.9.9"]
blocklist_sources = ["urlhaus", "phishtank", "coinblockerlists"]
psl_stale_warning_days = 45     # warning kalau lapis dinamis PSL belum refresh sekian hari, lihat ARCHITECTURE.md 3.7
integration_mode = "auto"       # auto (deteksi saat instalasi), takeover, chain_upstream, disabled, lihat ARCHITECTURE.md 3.7
chain_upstream_listen_port = 5353  # dipakai kalau integration_mode = chain_upstream, port lokal alternatif

[ip_reputation_filter]
enabled = true
feed_sources = ["feodotracker", "spamhaus_drop", "coinblockerlists"]
ttl_days = 10                   # lebih pendek dari domain blocklist karena IP lebih sering di-recycle
stale_warning_days = 7          # sama prinsipnya dengan psl_stale_warning_days
repeated_attempt_threshold_count = 3       # ambang percobaan konek ke IP blocklist sebelum proses itu sendiri masuk containment
repeated_attempt_threshold_window_seconds = 300

[trust_cache]
build_directory_ttl_seconds = 14400   # 4 jam default, sliding window, lihat DECISION_ENGINE.md Tier 3b
build_directory_patterns = ["**/target/debug/**", "**/target/release/**", "**/dist/**", "**/build/**", "**/out/**"]

[browser_extension]
enabled = true
enforce_domain_blocklist = true
form_action_mismatch_heuristic = true
trusted_identity_providers = ["accounts.google.com", "login.microsoftonline.com", "github.com", "appleid.apple.com", "*.okta.com", "*.auth0.com"]
blocklist_refresh_via = "vigil-core"    # ekstensi tidak fetch sendiri, selalu lewat native messaging ke vigil-core

[notifications]
style = "native"                # native, minimal, silent_log_only
prompt_timeout_seconds = 60
default_action_on_timeout = "allow_once"   # jangan pernah "block" tanpa konfirmasi, lihat AGENTS.md
```

## 3. Detail Field `[general]`

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `log_level` | string | `"info"` | Level logging, gunakan `debug` hanya untuk troubleshooting, bukan default produksi |
| `telemetry_enabled` | bool | `false` | Wajib default false sesuai `AGENTS.md`, harus ada penjelasan jelas di UI saat user mengaktifkan |
| `update_channel` | string | `"stable"` | Menentukan sumber update signature dan binary |

## 4. Detail Field `[resource_limits]`

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `max_cpu_percent_idle` | float | `1.0` | Target dari `PRD.md` bagian 6.1, dipakai sebagai acuan alert internal kalau daemon melebihi ini secara konsisten |
| `max_memory_mb_idle` | integer | `100` | Sama, acuan bukan hard limit yang mematikan proses |
| `scan_queue_max_concurrent` | string/integer | `"auto"` | `"auto"` menghitung `max(1, jumlah_core / 4)` saat startup, atau isi angka tetap untuk override manual. Lihat `docs/ARCHITECTURE.md` bagian 3.4.1 Layer 4 |
| `scan_priority` | string | `"low"` | Prioritas OS scheduling untuk scan worker, supaya tidak berebut resource dengan aplikasi foreground |
| `max_scan_file_size_mb` | integer | `200` | Ambang ukuran file untuk dialihkan ke scan mmap/background, bukan blocking di jalur on-access |
| `adaptive_backoff_on_high_load` | bool | `true` | Kurangi concurrency scan otomatis kalau load sistem dari aplikasi lain sedang tinggi |

## 5. Detail Field `[incident_response]`

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `mass_kill_circuit_breaker_count` | integer | `5` | Ambang jumlah proses auto-terminate dalam satu window sebelum sistem berhenti melanjutkan aksi otomatis, lihat `docs/DECISION_ENGINE.md` bagian 9 |
| `mass_kill_circuit_breaker_window_seconds` | integer | `60` | Panjang window waktu untuk hitungan di atas |
| `quarantine_directory` | string | `"default"` | Lokasi karantina file, `"default"` memakai subfolder di bawah storage path OS (`docs/ARCHITECTURE.md` bagian 3.5) |
| `freeze_before_kill` | bool | `true` | Containment (suspend proses) wajib sebelum terminate, mencegah dead man's switch/watchdog malware bereaksi terhadap kill langsung, lihat `docs/DECISION_ENGINE.md` bagian 9 |
| `network_isolate_before_kill` | bool | `true` | Putus semua koneksi jaringan PID yang di-flag sebelum terminate, bukan cuma koneksi ke IP reputasi jahat |
| `filesystem_block_before_kill` | bool | `true` | Blok write/unlink lebih lanjut dari PID yang di-flag sebelum terminate, mencegah kerusakan lanjutan |
| `containment_observation_window_ms` | integer | `500` | Jendela waktu memantau child process baru dari PID yang di-flag sebelum lanjut ke tahap terminate |

## 6. Detail Field `[dns_filter]`

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `enabled` | bool | `true` | Mengaktifkan DNS proxy lokal |
| `listen_address` | string | `"127.0.0.1:53"` | Alamat listen DNS proxy |
| `upstream` | array | `["1.1.1.1", "9.9.9.9"]` | Resolver upstream setelah filtering |
| `blocklist_sources` | array | `["urlhaus", "phishtank", "coinblockerlists"]` | Sumber blocklist reputasi domain/URL. `coinblockerlists` khusus domain mining pool dikenal |
| `psl_stale_warning_days` | integer | `45` | Ambang hari untuk warning kalau lapis dinamis Public Suffix List belum berhasil refresh, lihat `docs/ARCHITECTURE.md` bagian 3.7 |
| `integration_mode` | string | `"auto"` | `auto` mendeteksi resolver lain saat instalasi dan menyajikan pilihan ke user, atau override manual: `takeover`, `chain_upstream`, `disabled`, lihat `docs/ARCHITECTURE.md` bagian 3.7 |
| `chain_upstream_listen_port` | integer | `5353` | Port lokal yang dipakai Vigil kalau `integration_mode = chain_upstream`, supaya tidak berebut port 53 dengan resolver/proxy lain yang sudah ada |

## 7. Detail Field `[ip_reputation_filter]`

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `enabled` | bool | `true` | Mengaktifkan IP Reputation Filter, lihat `docs/ARCHITECTURE.md` bagian 3.8 |
| `feed_sources` | array | `["feodotracker", "spamhaus_drop", "coinblockerlists"]` | Sumber feed reputasi IP, curated khusus C2/malware dan mining pool, bukan broad abuse list |
| `ttl_days` | integer | `10` | TTL entry blocklist IP, lebih pendek dari domain karena IP lebih sering di-recycle/reassign |
| `stale_warning_days` | integer | `7` | Ambang hari untuk warning kalau feed belum berhasil refresh, prinsip sama dengan `psl_stale_warning_days` |
| `repeated_attempt_threshold_count` | integer | `3` | Jumlah percobaan koneksi berbeda ke IP blocklist dalam satu window sebelum proses itu sendiri masuk containment penuh, lihat `docs/DECISION_ENGINE.md` bagian 5 poin 5 |
| `repeated_attempt_threshold_window_seconds` | integer | `300` | Panjang window waktu untuk hitungan di atas |

## 8. Detail Field `[trust_cache]`

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `build_directory_ttl_seconds` | integer | `14400` (4 jam) | TTL sliding window untuk Ephemeral Trust Cache, lihat `docs/DECISION_ENGINE.md` Tier 3b |
| `build_directory_patterns` | array | lihat contoh di bagian 2 | Pola direktori yang eligible untuk cache ini, terpisah dari pola exclusion ransomware Tier 5 meski sering tumpang tindih |

## 9. Detail Field `[browser_extension]`

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `enabled` | bool | `true` | Mengaktifkan integrasi native messaging dengan `vigil-browser-extension`, lihat `docs/ARCHITECTURE.md` bagian 3.9 |
| `enforce_domain_blocklist` | bool | `true` | Enforce blocklist domain reputasi (phishing, mining pool) di level page-load lewat ekstensi |
| `form_action_mismatch_heuristic` | bool | `true` | Aktifkan heuristik form login yang submit ke origin berbeda |
| `trusted_identity_providers` | array | lihat contoh di bagian 2 | Domain identity provider yang dikecualikan dari heuristik form-action-mismatch supaya SSO/OAuth normal tidak salah tangkap |
| `blocklist_refresh_via` | string | `"vigil-core"` | Sumber refresh blocklist untuk ekstensi, selalu lewat native messaging ke `vigil-core`, tidak pernah fetch langsung dari ekstensi ke server luar |

## 10. Detail Field `[notifications]`

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `style` | string | `"native"` | `native` (notifikasi OS standar), `minimal` (indikator kecil tanpa popup mengganggu), `silent_log_only` (tidak ada notifikasi visual, cuma tercatat di audit log, untuk user yang tidak ingin terganggu sama sekali) |
| `prompt_timeout_seconds` | integer | `60` | Waktu tunggu sebelum `default_action_on_timeout` berlaku untuk kasus `PromptUser` yang tidak dijawab |
| `default_action_on_timeout` | string | `"allow_once"` | Aksi default kalau user tidak merespons prompt dalam `prompt_timeout_seconds`. WAJIB `allow_once` atau setara yang reversibel, TIDAK BOLEH bernilai yang setara dengan block permanen otomatis tanpa konfirmasi, lihat `AGENTS.md` bagian 1 poin 3 dan validasi di bagian 12 |

## 11. Detail Field `[scoring]`

Lihat `docs/DECISION_ENGINE.md` bagian 4 untuk penjelasan formula. Field di sini memungkinkan tuning tanpa rebuild binary, tapi perubahan default value di kode sumber tetap harus lewat proses di bagian 4 dokumen tersebut (pengujian terhadap suite regresi).

## 12. Validasi Config

`vigil-config` wajib melakukan validasi berikut saat parsing, dan menolak start daemon (fail closed ke kondisi aman, bukan fail open tanpa proteksi) kalau validasi gagal:

- Jumlah `weight_*` di `[scoring]` harus sama dengan 1.0 (dengan toleransi floating point kecil).
- `threshold_block` harus lebih besar dari `threshold_prompt`.
- Pattern glob di `path_pattern` dan `domain_allowlist` harus valid secara sintaks sebelum dipakai runtime.
- `default_action_on_timeout` tidak boleh bernilai yang setara dengan block otomatis tanpa konfirmasi, sesuai prinsip di `AGENTS.md` bagian 1 poin 3.
- `dns_filter.integration_mode` harus salah satu dari `auto`, `takeover`, `chain_upstream`, `disabled`, nilai lain ditolak saat parsing.
- `incident_response.freeze_before_kill`, `network_isolate_before_kill`, `filesystem_block_before_kill` tidak boleh diset `false` semuanya sekaligus tanpa peringatan eksplisit ke user saat instalasi, karena itu berarti menghilangkan seluruh mekanisme containment di `docs/DECISION_ENGINE.md` bagian 9 dan kembali ke kill langsung.
- `mass_kill_circuit_breaker_count` harus bernilai positif (minimal 1), nilai 0 akan membuat sistem tidak pernah bisa auto-terminate apapun yang mungkin bukan maksud user, tetap izinkan tapi wajib tampilkan warning eksplisit saat parsing.
- `ttl_days`/`stale_warning_days` di `[ip_reputation_filter]` dan field TTL sejenis lainnya harus bernilai positif.
- `chain_upstream_listen_port` tidak boleh sama dengan port yang sudah dipakai `listen_address` (default 53), untuk mencegah konflik dengan dirinya sendiri.

## 13. Field Locked oleh Admin (Multi User Environment)

Untuk kasus mesin dipakai banyak user tapi admin ingin memastikan baseline proteksi tidak bisa dimatikan user biasa:

```toml
[locked_fields]
paths = ["resource_limits", "scoring.threshold_block"]
```

Field yang namanya cocok dengan pattern di `locked_fields` tidak bisa dioverride oleh config per user, hanya bisa diubah lewat config sistem wide yang butuh akses admin/root.

## 14. Contoh File Konfigurasi Minimal

```toml
[general]
log_level = "info"
telemetry_enabled = false

[dns_filter]
enabled = true
```

Field yang tidak disebutkan memakai default yang tercatat di dokumen ini. Jangan buat daemon bergantung pada field yang tidak punya default terdokumentasi, karena itu berarti config kosong bisa membuat daemon gagal start atau berjalan dengan state tidak terduga.

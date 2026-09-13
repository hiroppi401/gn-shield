# Task: Perbaiki DNS proxy liveness monitoring + hardening tambahan

## Konteks

Commit `f078beb` (`feat(core,ipc): make module status in IPC reflect live runtime health`)
sudah bagus untuk `LinuxFsSensor` dan `EbpfIpReputationFilter` — keduanya pakai RAII `Guard`
dengan `Drop` sehingga flag `Arc<AtomicBool>` otomatis jadi `false` kalau thread keluar lewat
`break` ATAUPUN panic.

Tapi untuk **DNS proxy**, pola yang sama TIDAK benar-benar bekerja karena bug arsitektur:

Di `crates/gn-shield-core/src/main.rs` (sekitar baris 460-490):
```rust
match dns_clone.run_udp_listeners().await {
    Ok(()) => {
        let _guard = Guard(Arc::clone(&dns_alive));
        dns_alive.store(true, Ordering::Relaxed);
        println!("DnsProxyServer active on port {dns_port} (dual-stack IPv4/IPv6).");
        while !dns_shutdown.load(Ordering::Relaxed) {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
        dns_alive.store(false, Ordering::Relaxed);
    }
    Err(e) => { ... }
}
```

Dan di `crates/gn-shield-dns/src/server.rs`, `run_udp_listeners()`:
```rust
pub async fn run_udp_listeners(self: Arc<Self>) -> Result<(), String> {
    let v4_sock = Arc::new(UdpSocket::bind(self.listen_ipv4).await?);
    let v6_sock = Arc::new(UdpSocket::bind(self.listen_ipv6).await?);

    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = v4_sock_clone.recv_from(&mut buf).await {
            // proses query...
        }
        // loop selesai secara diam-diam kalau recv_from error — TIDAK ADA LOGGING
    });

    tokio::spawn(async move {
        // sama untuk v6
    });

    Ok(()) // <-- return LANGSUNG setelah spawn, TIDAK menunggu listener selesai
}
```

### Bug inti
`run_udp_listeners()` tidak blocking — dia cuma bind socket, `tokio::spawn` dua task
(listener loop v4 dan v6) secara fire-and-forget (tidak ada `JoinHandle` yang disimpan), lalu
langsung `return Ok(())`. Akibatnya:

1. **False positive (status bilang aktif padahal mati):** Kalau salah satu loop `recv_from`
   berhenti karena socket error, loop itu selesai **tanpa logging sama sekali** dan
   **tanpa memberi tahu supervisor**. `dns_alive` tidak pernah tahu dan tetap `true` selamanya
   — persis bug yang seharusnya sudah diperbaiki di commit ini, cuma pindah satu lapis lebih
   dalam (dari daemon-level ke dalam `run_udp_listeners` sendiri).
2. **False negative saat shutdown (status bilang mati padahal listener masih hidup):** Saat
   `dns_shutdown` terpicu, supervisor di `main.rs` cuma keluar dari while-loop pemantauan lalu
   set `dns_alive = false` — tapi tidak pernah mengirim sinyal cancel ke kedua task v4/v6 yang
   sesungguhnya melakukan `recv_from`. Socket-nya tetap bound dan task-nya tetap berjalan
   sampai seluruh proses/tokio runtime mati. Ini tidak fatal saat proses exit total, tapi
   menghalangi kemungkinan graceful reload/restart tanpa restart proses penuh, dan secara
   semantik status yang dilaporkan salah.

## Tujuan
Buat `dns_filter_active` benar-benar reflektif terhadap kondisi nyata dua task listener
(v4 & v6), dan pastikan keduanya benar-benar berhenti (bukan cuma dilupakan) saat shutdown.

## Langkah kerja yang diharapkan

1. **Ubah signature `run_udp_listeners`** di `crates/gn-shield-dns/src/server.rs` agar
   menerima mekanisme cancellation, misalnya `tokio_util::sync::CancellationToken`
   (tambahkan dependency `tokio-util` kalau belum ada) atau `tokio::sync::watch::Receiver<bool>`.
   Signature baru kira-kira:
   ```rust
   pub async fn run_udp_listeners(
       self: Arc<Self>,
       cancel: CancellationToken,
   ) -> Result<(JoinHandle<()>, JoinHandle<()>), String>
   ```
   atau kembalikan struct berisi kedua `JoinHandle` (jangan buang lewat `tokio::spawn` tanpa
   disimpan).

2. **Sisipkan cek cancellation di dalam masing-masing loop v4/v6**, misalnya:
   ```rust
   loop {
       tokio::select! {
           _ = cancel.cancelled() => break,
           res = v4_sock_clone.recv_from(&mut buf) => {
               match res {
                   Ok((len, peer)) => { /* proses seperti sekarang */ }
                   Err(e) => {
                       eprintln!("DNS v4 listener recv_from error, stopping: {e}");
                       break;
                   }
               }
           }
       }
   }
   ```
   Lakukan hal yang sama untuk task v6. **Tambahkan logging saat loop berhenti karena error**
   (poin hardening tambahan dari review — saat ini errornya ditelan tanpa jejak sama sekali).

3. **Di `main.rs`, ganti supervisor DNS jadi benar-benar memonitor kedua `JoinHandle`.**
   Pola yang diharapkan (selaras dengan pola `Guard`/`Drop` yang sudah dipakai di
   `fs_thread`/`ip_thread`):
   ```rust
   tokio::spawn(async move {
       match dns_clone.run_udp_listeners(cancel_token.clone()).await {
           Ok((v4_handle, v6_handle)) => {
               dns_alive.store(true, Ordering::Relaxed);
               println!("DnsProxyServer active on port {dns_port} (dual-stack IPv4/IPv6).");

               tokio::select! {
                   _ = async { let _ = v4_handle.await; } => {
                       eprintln!("Warning: DNS IPv4 listener task exited unexpectedly.");
                   }
                   _ = async { let _ = v6_handle.await; } => {
                       eprintln!("Warning: DNS IPv6 listener task exited unexpectedly.");
                   }
                   _ = async {
                       while !dns_shutdown.load(Ordering::Relaxed) {
                           tokio::time::sleep(Duration::from_millis(200)).await;
                       }
                   } => {
                       cancel_token.cancel();
                       let _ = v4_handle.await;
                       let _ = v6_handle.await;
                   }
               }
               dns_alive.store(false, Ordering::Relaxed);
           }
           Err(e) => {
               dns_alive.store(false, Ordering::Relaxed);
               eprintln!("Warning: DNS proxy server listener failed on port {dns_port}: {e}");
           }
       }
   });
   ```
   Intinya: **task v4/v6 mati sendiri (crash) HARUS memicu `dns_alive = false` segera**, bukan
   cuma saat shutdown yang disengaja. Boleh pakai pendekatan lain (channel, watch, dsb) asal
   properti ini terpenuhi.

4. **Pastikan `cancel_token.cancel()` benar-benar dipanggil saat shutdown**, dan tunggu
   (`.await`) kedua `JoinHandle` sampai selesai sebelum melanjutkan proses shutdown daemon —
   supaya socket benar-benar ditutup, bukan cuma flag yang diubah.

5. **Hardening tambahan (dari catatan review sebelumnya, sertakan sekalian dalam PR ini):**
   - `breach_checker_active` dan `browser_companion_active` saat ini hanya mencerminkan
     `config.*.enabled`, BUKAN kondisi runtime nyata (karena memang belum ada proses/loop
     background untuk keduanya). Ini boleh dibiarkan APA ADANYA untuk sekarang, tapi **tambahkan
     komentar eksplisit di kode** (di atas baris yang men-set flag ini) yang menjelaskan bahwa
     kedua flag ini merepresentasikan "enabled di config", bukan "runtime health", supaya tidak
     ada yang salah asumsi nanti kalau baca `ModuleHealth` dan mengira semua field sama semantiknya.
   - Review semua tempat lain yang memanggil `.await` pada operasi socket/IO dalam
     `gn-shield-dns` untuk memastikan tidak ada pola serupa (fire-and-forget spawn tanpa
     handle) di luar `run_udp_listeners`.

6. **Update test.**
   - Tambahkan test baru di `crates/gn-shield-dns/src/server.rs` atau
     `crates/gn-shield-core/src/main.rs`-level integration test yang membuktikan: kalau socket
     v4 (atau task-nya) dipaksa berhenti (misal simulasikan dengan menutup socket dari luar,
     atau memakai mock port yang sudah dipakai), maka `dns_alive` benar-benar berubah jadi
     `false` **tanpa menunggu sinyal shutdown eksplisit**.
   - Tambahkan test yang membuktikan `cancel_token.cancel()` benar-benar menghentikan kedua
     task listener (misalnya cek bahwa `JoinHandle` selesai dalam waktu wajar setelah cancel).
   - Test lama (`test_ipc_status_reflects_runtime_module_health_and_dead_module`, dan test-test
     di `fase5_breach_and_fase6_cli_regression.rs`) harus tetap lolos tanpa perubahan besar pada
     assertion-nya.

7. **Jangan ubah** logika `config.validate()` / fail-closed startup, dan jangan ubah perilaku
   `LinuxFsSensor`/`EbpfIpReputationFilter` yang sudah benar (pola `Guard`/`Drop`-nya sudah
   bagus, jadikan referensi gaya untuk DNS, jangan direfactor ulang).

## Definition of done
- [ ] `run_udp_listeners` (atau pemanggilnya di `main.rs`) benar-benar memonitor kedua task
      listener v4/v6 lewat `JoinHandle`, bukan fire-and-forget.
- [ ] Kalau salah satu listener v4/v6 mati karena error, `dns_alive` langsung jadi `false` dan
      ada log peringatan — tanpa harus menunggu sinyal shutdown.
- [ ] Saat shutdown daemon, kedua task listener benar-benar di-cancel dan socket ditutup
      (bukan cuma flag yang berubah), dibuktikan lewat `.await` pada `JoinHandle` sampai selesai.
- [ ] Error di dalam loop `recv_from` tidak lagi ditelan diam-diam — ada `eprintln!`/logging.
- [ ] Komentar eksplisit ditambahkan untuk `breach_checker_active` dan
      `browser_companion_active` yang menjelaskan semantik "config enabled" vs "runtime health".
- [ ] Test baru untuk skenario "listener crash → status jadi false tanpa shutdown eksplisit"
      dan "cancel benar-benar menghentikan task".
- [ ] Semua test lama (termasuk yang dari commit `f078beb`) tetap lolos.
- [ ] Tidak ada perubahan pada logika `config.validate()` atau urutan fail-closed startup.
- [ ] `cargo check` dan `cargo test` untuk `gn-shield-core` dan `gn-shield-dns` lolos tanpa
      error/warning baru.

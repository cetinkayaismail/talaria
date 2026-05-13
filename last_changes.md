# Son Değişiklikler (Last Changes)

Bu güncelleme ile Talaria'nın analiz yetenekleri derinleştirilmiş ve 2026 yılının en kritik çekirdek zafiyetleri eklenmiştir.

## Yeni Kernel Zafiyetleri (2026 Güncellemesi)
- **Dirty Frag (CVE-2026-43284 / CVE-2026-43500)**: "Dirty Pipe" zafiyetinin halefi olarak kabul edilen ve page cache manipulation yöntemiyle root yetkisi sağlayan deterministik bir LPE zafiyeti eklendi.
- **Copy Fail (CVE-2026-31431)**: Kernel kripto alt sistemindeki (`algif_aead`) mantık hatası üzerinden root erişimi sağlayan zafiyet eklendi.
- **AF_UNIX Diagnostic Race (CVE-2026-31673)**: Soket teşhislerindeki senkronizasyon hatası üzerinden yetki yükseltmeye imkan tanıyan zafiyet eklendi.

## Profesyonel Raporlama Modu (--professional / -p)
Kullanıcıların sızma testi veya denetim (audit) raporları hazırlarken daha sade çıktılar alabilmesi için profesyonel mod eklenmiştir. Bu mod aktif edildiğinde, CTF odaklı "adım adım exploit" ipuçları rapordan temizlenerek sadece teknik bulgu ve risk analizi sunulur. Yardım menüsü ve kullanım dökümanları bu yeni bayrağı içerecek şekilde güncellenmiştir.

## SUID/SGID Analiz Geliştirmeleri (SO Hijacking)
SUID modülü artık sadece dosya isimlerine bakmakla kalmıyor, aynı zamanda binary dosyaların ELF başlıklarını inceleyerek RPATH ve RUNPATH değerlerini analiz ediyor. Eğer bir binary, dışarıdan kütüphane çağırdığı dizinler üzerinde yazma yetkisine sahipse, bu durum potansiyel bir "Shared Object Hijacking" vektörü olarak raporlanmaktadır.

## Cron İşleri ve Wildcard Saldırıları
Zamanlanmış görevler (cronjobs) içerisindeki komut analizleri güçlendirilmiştir. Özellikle 'tar *', 'chmod *' ve 'chown *' gibi joker karakter (wildcard) kullanımı içeren ve dosya ismi üzerinden komut çalıştırmaya (command injection) izin veren tehlikeli kalıplar artık otomatik olarak tespit edilmektedir.

## Hassas Dosya Taraması (History, Cloud & Logs)
Sırlar (Secrets) modülünün tarama kapsamı genişletilmiştir. Artık sadece standart yapılandırma dosyaları değil, aynı zamanda terminal geçmişi (.bash_history, .zsh_history), bulut servis yapılandırmaları (.aws, .kube) ve okunabilir durumdaki sistem logları (/var/log/auth.log, /var/log/syslog) içindeki hassas bilgiler (şifreler, tokenlar, API anahtarları) taranmaktadır.

## Kritik Grup Analizi ve Exploit Rehberi
Tehlikeli grup üyelikleri (LXD, Docker, Disk vb.) tespit edildiğinde, bu durumun nasıl istismar edilebileceğine dair teknik açıklamalar ve (profesyonel mod kapalıyken) hazır exploit komutları rapora dahil edilmiştir. Özellikle LXD grubu üzerinden host sistemin kök dizinine erişim gibi kritik vektörler detaylandırılmıştır.

## Hedefli Kök Dizin Taraması (Targeted Root Scan)
Kök dizin (/) üzerindeki taramalar performansı düşürmemesi için sınırlandırılmıştı. Ancak kritik "root ssh key" gibi açıkları kaçırmamak için sadece belirli gizli klasörleri (/.ssh, /.aws, /.backup vb.) hedef alan, recursive olmayan (alt dizinlere inmeyen) çok hızlı bir tarama mekanizması eklenmiştir. Bu sayede en kritik "hidden" sızıntılar sistem yükü yaratmadan tespit edilebilmektedir.

## Yerel Servis Denetimi (Local Service Audit)
Sistemde sadece yerel ağda (localhost) koşan ve şifresiz erişime izin veren MySQL ve Redis gibi kritik servisleri tespit eden yeni bir modül eklenmiştir. Özellikle root yetkisiyle çalışan MySQL servislerine boş şifre ile girilebilmesi gibi "User Defined Functions" (UDF) üzerinden root shell almayı sağlayan tehlikeli yapılandırmalar artık otomatik olarak raporlanmaktadır.

## Binary Strings PATH Hijack Analizi
Sadece scriptler değil, artık derlenmiş (binary) SUID/SGID dosyaları da PATH hijacking riskine karşı taranmaktadır. Performans kaybını önlemek için sadece standart dışı dizinlerdeki (örneğin /usr/local/bin) binary'lerin ilk 100 KB'lık kısmı taranır ve içindeki 'service', 'tar' gibi tehlikeli komut çağrıları analiz edilir. Bu sayede 'suid-env' gibi klasik sömürülebilir binary'ler milisaniyeler içinde tespit edilir.

## Tarayıcı Sırları ve Modern Paket Denetimi
- **Tarayıcı Sırları:** Firefox, Chrome, Brave ve Opera gibi popüler tarayıcıların profil dizinleri, kayıtlı şifreleri (logins.json), cookie veritabanları ve geçmiş dosyaları artık otomatik olarak tespit edilmektedir.
- **Paket Denetimi (Packages):** `doas.conf` (nopass ayarları), Snapd soket yetkileri ve Flatpak dizin izinleri gibi modern paket/yetki yöneticisi zafiyetleri için yeni bir modül eklenmiştir.

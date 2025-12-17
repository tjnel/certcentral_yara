import "pe"

rule MAL_Compromised_Cert_ZhongStealer_GlobalSign_7EAD677A7DD7F660379D116A {
   meta:
      description         = "Detects ZhongStealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-01"
      version             = "1.0"

      hash                = "d58859ddc52f98e48d32f47b000970ad03e807b8eeb3a1aae7d4af2721b43ecf"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "Hena Luxion Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7e:ad:67:7a:7d:d7:f6:60:37:9d:11:6a"
      cert_thumbprint     = "6DEC33D0A800435FB16E222F8F48D6F0BD650F0D"
      cert_valid_from     = "2024-11-01"
      cert_valid_to       = "2025-11-02"

      country             = "CN"
      state               = "Henan"
      locality            = "Zhengzhou"
      email               = "???"
      rdn_serial_number   = "91410104MA447T3JX7"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7e:ad:67:7a:7d:d7:f6:60:37:9d:11:6a"
      )
}

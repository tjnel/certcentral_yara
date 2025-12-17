import "pe"

rule MAL_Compromised_Cert_LummaStealer_GlobalSign_49EF8191E6CFB0F25A125B62 {
   meta:
      description         = "Detects LummaStealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-03"
      version             = "1.0"

      hash                = "11eec5d71c7fadae9d7176448d8fff3de44ec8d3b4df86f0eca59e06adf202d3"
      malware             = "LummaStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "ООО Мб-Сигма"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "49:ef:81:91:e6:cf:b0:f2:5a:12:5b:62"
      cert_thumbprint     = "0702BA0245DF74C814F328A076E8D4D1504E17F0"
      cert_valid_from     = "2025-02-03"
      cert_valid_to       = "2026-02-04"

      country             = "RU"
      state               = "Санкт-Петербург"
      locality            = "Санкт-Петербург"
      email               = "mb.sigma@mail.ru"
      rdn_serial_number   = "1207800050622"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "49:ef:81:91:e6:cf:b0:f2:5a:12:5b:62"
      )
}

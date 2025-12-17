import "pe"

rule MAL_Compromised_Cert_FakeBat_Certum_0B4003DD1778E77C7B3230A4962E5558 {
   meta:
      description         = "Detects FakeBat with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-13"
      version             = "1.0"

      hash                = "68b904897bf6a9124c75dec50fc8cb292069491357785f05f667f91096736960"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "ExpoWave Technology OÜ"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "0b:40:03:dd:17:78:e7:7c:7b:32:30:a4:96:2e:55:58"
      cert_thumbprint     = "2FE6D426B391CC9DE6CB57EB9C9E9AC0B61CE857"
      cert_valid_from     = "2023-09-13"
      cert_valid_to       = "2024-09-12"

      country             = "EE"
      state               = "Harju County"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "16812266"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "0b:40:03:dd:17:78:e7:7c:7b:32:30:a4:96:2e:55:58"
      )
}

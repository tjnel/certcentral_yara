import "pe"

rule MAL_Compromised_Cert_Trojan_Win64_Zapchast_ffs_Certum_33C6CBB8827B6F181A449D2027A94E45 {
   meta:
      description         = "Detects Trojan.Win64.Zapchast.ffs with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-27"
      version             = "1.0"

      hash                = "6de97e8d1fce40daaa3453d5ec1a74741b7139f160a02dca235c62be1aaf08f9"
      malware             = "Trojan.Win64.Zapchast.ffs"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Capybara Technology Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "33:c6:cb:b8:82:7b:6f:18:1a:44:9d:20:27:a9:4e:45"
      cert_thumbprint     = "937b9ea609fa9f33a542ebb196733740509c7c720bd72f5e16c9d1921f32ef57"
      cert_valid_from     = "2025-04-27"
      cert_valid_to       = "2026-04-27"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "33:c6:cb:b8:82:7b:6f:18:1a:44:9d:20:27:a9:4e:45"
      )
}

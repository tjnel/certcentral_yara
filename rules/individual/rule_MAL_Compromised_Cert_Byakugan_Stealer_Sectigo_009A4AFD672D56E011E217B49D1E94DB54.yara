import "pe"

rule MAL_Compromised_Cert_Byakugan_Stealer_Sectigo_009A4AFD672D56E011E217B49D1E94DB54 {
   meta:
      description         = "Detects Byakugan Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-26"
      version             = "1.0"

      hash                = "dc1ad7b55e0cbd21f31676a2206c66f050afd644d9b01773c7e5e64091e2db81"
      malware             = "Byakugan Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CubTiger Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:9a:4a:fd:67:2d:56:e0:11:e2:17:b4:9d:1e:94:db:54"
      cert_thumbprint     = "F52E0DAAA23CE9FD0ED952052348D14A37223A47"
      cert_valid_from     = "2025-09-26"
      cert_valid_to       = "2026-09-26"

      country             = "CN"
      state               = "Beijing Shi"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91110229MA01R14F61"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:9a:4a:fd:67:2d:56:e0:11:e2:17:b4:9d:1e:94:db:54"
      )
}

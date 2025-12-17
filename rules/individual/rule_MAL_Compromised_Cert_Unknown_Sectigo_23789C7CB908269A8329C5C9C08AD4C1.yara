import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_23789C7CB908269A8329C5C9C08AD4C1 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-17"
      version             = "1.0"

      hash                = "90d7f4352676535a9f76083ac0a63a6c0e11e08dbd1084f6ba28ec0eb69ada3e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Pingding Jiangxin Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "23:78:9c:7c:b9:08:26:9a:83:29:c5:c9:c0:8a:d4:c1"
      cert_thumbprint     = "D046DC77B12EDD154CDF15B9D419915AC8401CA3"
      cert_valid_from     = "2025-06-17"
      cert_valid_to       = "2026-06-17"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "23:78:9c:7c:b9:08:26:9a:83:29:c5:c9:c0:8a:d4:c1"
      )
}

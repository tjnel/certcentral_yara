import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_605BD85F34A3E143941C0715 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-12"
      version             = "1.0"

      hash                = "dbbc491d1ffd9d86e0f69454c1b52ff44c370e1777f332098f4e3842fd59e92e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Pingding Jiangxin Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "60:5b:d8:5f:34:a3:e1:43:94:1c:07:15"
      cert_thumbprint     = "429908F1BAFA42E7CDDC4527AE08F7196BF93DCF"
      cert_valid_from     = "2025-06-12"
      cert_valid_to       = "2026-06-13"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Yangquan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "60:5b:d8:5f:34:a3:e1:43:94:1c:07:15"
      )
}

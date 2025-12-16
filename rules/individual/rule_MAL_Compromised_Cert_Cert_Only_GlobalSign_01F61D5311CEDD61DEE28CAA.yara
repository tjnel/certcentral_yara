import "pe"

rule MAL_Compromised_Cert_Cert_Only_GlobalSign_01F61D5311CEDD61DEE28CAA {
   meta:
      description         = "Detects Cert Only with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-11"
      version             = "1.0"

      hash                = "eec8d8dbdc517184ddfa7353ed89e4ac4d2e6c2fefef2a8c4e2c81bb4b6a9047"
      malware             = "Cert Only"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nine Rivers Sky Roar Commit Trade Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "01:f6:1d:53:11:ce:dd:61:de:e2:8c:aa"
      cert_thumbprint     = "2DAE7C97B1CE082B6FA5B6CC0786BAD87AFEF563"
      cert_valid_from     = "2024-03-11"
      cert_valid_to       = "2025-03-12"

      country             = "CN"
      state               = "Jiangxi"
      locality            = "Jiujiang"
      email               = "???"
      rdn_serial_number   = "91360402MACHADCC93"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "01:f6:1d:53:11:ce:dd:61:de:e2:8c:aa"
      )
}

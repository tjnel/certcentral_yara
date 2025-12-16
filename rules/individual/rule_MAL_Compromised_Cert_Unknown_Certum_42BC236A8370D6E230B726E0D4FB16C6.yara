import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_42BC236A8370D6E230B726E0D4FB16C6 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-23"
      version             = "1.0"

      hash                = "edef0a42ef8dede49f47c763238c8caea2ccb45a9af69362c41f1d95e8a19540"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Menghu Network Technology (Beijing) Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "42:bc:23:6a:83:70:d6:e2:30:b7:26:e0:d4:fb:16:c6"
      cert_thumbprint     = "17C88198B4F3343FDDFC002BC94BD9098EC39FB2"
      cert_valid_from     = "2024-09-23"
      cert_valid_to       = "2025-09-23"

      country             = "CN"
      state               = "Beijing"
      locality            = "Beijing"
      email               = "???"
      rdn_serial_number   = "91110229MA01R14F61"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "42:bc:23:6a:83:70:d6:e2:30:b7:26:e0:d4:fb:16:c6"
      )
}

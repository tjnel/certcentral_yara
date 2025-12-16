import "pe"

rule MAL_Compromised_Cert_ValleyRat_Certum_65620C1D74A8FD9630E9F2BF6281A61A {
   meta:
      description         = "Detects ValleyRat with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-11"
      version             = "1.0"

      hash                = "5085b09b4bb5a017f13e0d4c970184518370b93d5e464bf5fbad8d522b42fd57"
      malware             = "ValleyRat"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Meisi Software Development （Guangxi）Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "65:62:0c:1d:74:a8:fd:96:30:e9:f2:bf:62:81:a6:1a"
      cert_thumbprint     = "6366384F040F581885BBC875C4C641B347692B55"
      cert_valid_from     = "2025-07-11"
      cert_valid_to       = "2026-07-11"

      country             = "CN"
      state               = "Guangxi"
      locality            = "Yulin"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "65:62:0c:1d:74:a8:fd:96:30:e9:f2:bf:62:81:a6:1a"
      )
}

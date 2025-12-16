import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_36F44D0D998049FD13A86F974962E7DE {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-11"
      version             = "1.0"

      hash                = "e8a8473c1e01688d370bbb1968b6361264c56a65ddbb31f8278ac618618f4efa"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Kede Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "36:f4:4d:0d:99:80:49:fd:13:a8:6f:97:49:62:e7:de"
      cert_thumbprint     = "C8114F47D8582234E66DBF277457750CD47EAF16"
      cert_valid_from     = "2024-09-11"
      cert_valid_to       = "2025-09-11"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310120MA1JJ0UL27"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "36:f4:4d:0d:99:80:49:fd:13:a8:6f:97:49:62:e7:de"
      )
}

import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_097B634740A6CF3A61F0AA5A62E940A6 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-17"
      version             = "1.0"

      hash                = "731a144baa1d2bd6b316a3b4408fe280a15d39c6998374169e5cec803ff0729a"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "武汉市领曼盾数字科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "09:7b:63:47:40:a6:cf:3a:61:f0:aa:5a:62:e9:40:a6"
      cert_thumbprint     = "E5BE43DC8A6C2E90443F3540B43540BE1CE5B81D"
      cert_valid_from     = "2025-11-17"
      cert_valid_to       = "2026-11-17"

      country             = "CN"
      state               = "Hubei"
      locality            = "Wuhan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "09:7b:63:47:40:a6:cf:3a:61:f0:aa:5a:62:e9:40:a6"
      )
}

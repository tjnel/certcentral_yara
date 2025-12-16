import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_5502C16C26DE07B5F0F3F238 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-15"
      version             = "1.0"

      hash                = "e2672f52404bf6cc190fac2218dc8a8424c112c71db9b9db94e7f14fa5e9d238"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "HANSHA ENGICON PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "55:02:c1:6c:26:de:07:b5:f0:f3:f2:38"
      cert_thumbprint     = "61DFABE4069BB465C161B889151538F9F759B2C7"
      cert_valid_from     = "2025-07-15"
      cert_valid_to       = "2026-07-16"

      country             = "IN"
      state               = "Bihar"
      locality            = "Samastipur"
      email               = "hanshaengicon@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "55:02:c1:6c:26:de:07:b5:f0:f3:f2:38"
      )
}

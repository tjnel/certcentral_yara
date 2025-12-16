import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_534F46E63E0FF143119ACA722330B8A7 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-12"
      version             = "1.0"

      hash                = "221bb9c2702a2081a8dc5722ffaf81d1f9fab4de3d93794fe8becd1a12013931"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "GOLORY VISIONS PRIVATE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "53:4f:46:e6:3e:0f:f1:43:11:9a:ca:72:23:30:b8:a7"
      cert_thumbprint     = "F79B4CBA32560BC0A46FBA364085C84000F7F3CB"
      cert_valid_from     = "2025-09-12"
      cert_valid_to       = "2026-09-12"

      country             = "IN"
      state               = "Delhi"
      locality            = "New Delhi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "53:4f:46:e6:3e:0f:f1:43:11:9a:ca:72:23:30:b8:a7"
      )
}

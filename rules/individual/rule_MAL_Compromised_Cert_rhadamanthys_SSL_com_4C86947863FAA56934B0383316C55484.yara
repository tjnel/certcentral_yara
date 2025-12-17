import "pe"

rule MAL_Compromised_Cert_rhadamanthys_SSL_com_4C86947863FAA56934B0383316C55484 {
   meta:
      description         = "Detects rhadamanthys with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-17"
      version             = "1.0"

      hash                = "76ab8496660eab79e88ce5f94f340201c923d5731706a3d788922c9c3bff2f1c"
      malware             = "rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Soft-cloud Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4c:86:94:78:63:fa:a5:69:34:b0:38:33:16:c5:54:84"
      cert_thumbprint     = "6DC85EA85373932064AAACB2E2700E07C10DE0E1"
      cert_valid_from     = "2025-03-17"
      cert_valid_to       = "2026-03-17"

      country             = "FI"
      state               = "Satakunta"
      locality            = "Säkylä"
      email               = "???"
      rdn_serial_number   = "3112306-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4c:86:94:78:63:fa:a5:69:34:b0:38:33:16:c5:54:84"
      )
}

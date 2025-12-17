import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_72FD654308155944BDAD4E0054F37E57 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-14"
      version             = "1.0"

      hash                = "5723793f48e3688ef7417f0f1cd7d76ae5635782e6b3f21a5b6937c7bfa6e583"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "It-Rex Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "72:fd:65:43:08:15:59:44:bd:ad:4e:00:54:f3:7e:57"
      cert_thumbprint     = "ED2BE232B85F1048839C45CD2B7F885F7E2D0B2F"
      cert_valid_from     = "2025-04-14"
      cert_valid_to       = "2026-04-13"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "3254547-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "72:fd:65:43:08:15:59:44:bd:ad:4e:00:54:f3:7e:57"
      )
}

import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_66811A7CBD25555F23EA3B1DA3391DCF {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-19"
      version             = "1.0"

      hash                = "b1e8e75ea54ea3e9a3297250489f26f6d5d1f950e75686b31359accc928bc4af"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "COBBLED STREETS EDUTECH PRIVATE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "66:81:1a:7c:bd:25:55:5f:23:ea:3b:1d:a3:39:1d:cf"
      cert_thumbprint     = "A2A79252FE95836BC4F8EE7128AF88F00FBF13A4"
      cert_valid_from     = "2025-09-19"
      cert_valid_to       = "2026-09-19"

      country             = "IN"
      state               = "Delhi"
      locality            = "New Delhi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "66:81:1a:7c:bd:25:55:5f:23:ea:3b:1d:a3:39:1d:cf"
      )
}

import "pe"

rule MAL_Compromised_Cert_XRed_SSL_com_28296E139B8B608FEA6FD820F54BABDD {
   meta:
      description         = "Detects XRed with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-24"
      version             = "1.0"

      hash                = "64d0fd6a5a62640f3ff0248c11ec8cb47e567964b717492b3da6d7135f4b6938"
      malware             = "XRed"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Learnos LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "28:29:6e:13:9b:8b:60:8f:ea:6f:d8:20:f5:4b:ab:dd"
      cert_thumbprint     = "BC4DCD10F68D24C490CD0C68D764A90BD3FC0799"
      cert_valid_from     = "2025-02-24"
      cert_valid_to       = "2026-02-22"

      country             = "US"
      state               = "Wyoming"
      locality            = "Sheridan"
      email               = "???"
      rdn_serial_number   = "2025-001597211"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "28:29:6e:13:9b:8b:60:8f:ea:6f:d8:20:f5:4b:ab:dd"
      )
}

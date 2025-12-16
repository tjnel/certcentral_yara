import "pe"

rule MAL_Compromised_Cert_Traffer_Mystix_SSL_com_084374CC276E43AC90AFFA80B1EF7C38 {
   meta:
      description         = "Detects Traffer (Mystix) with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-13"
      version             = "1.0"

      hash                = "8651f126047222ca0273f9d0000681538a5847f7e4a45f62af497f934df014e1"
      malware             = "Traffer (Mystix)"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Traitsense ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "08:43:74:cc:27:6e:43:ac:90:af:fa:80:b1:ef:7c:38"
      cert_thumbprint     = "8536E25936E97B6BDC9591AEECC0E3D5FC1F5BCD"
      cert_valid_from     = "2025-01-13"
      cert_valid_to       = "2026-01-13"

      country             = "DK"
      state               = "???"
      locality            = "Agerskov"
      email               = "???"
      rdn_serial_number   = "37751391"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "08:43:74:cc:27:6e:43:ac:90:af:fa:80:b1:ef:7c:38"
      )
}

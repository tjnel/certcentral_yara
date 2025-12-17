import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_084374CC276E43AC90AFFA80B1EF7C38 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-13"
      version             = "1.0"

      hash                = "e2f944cbcda22e6fd727f93514d11a7885f4bae6c6c5f33630e737b7c861907e"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

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

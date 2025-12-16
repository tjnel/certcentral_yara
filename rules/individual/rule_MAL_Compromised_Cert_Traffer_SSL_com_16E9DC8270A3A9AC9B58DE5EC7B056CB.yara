import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_16E9DC8270A3A9AC9B58DE5EC7B056CB {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-26"
      version             = "1.0"

      hash                = "b2031f5c2190f474165e58b28619030f4ec5e780a431bbe9941340fc348ff4d1"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BAG IT PTY LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "16:e9:dc:82:70:a3:a9:ac:9b:58:de:5e:c7:b0:56:cb"
      cert_thumbprint     = "839FAF8B95803A3639D27A7EA1D57C56C764D251"
      cert_valid_from     = "2025-05-26"
      cert_valid_to       = "2026-05-26"

      country             = "AU"
      state               = "New South Wales"
      locality            = "Sydney"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "16:e9:dc:82:70:a3:a9:ac:9b:58:de:5e:c7:b0:56:cb"
      )
}

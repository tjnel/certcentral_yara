import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_5A2921F8FF4E923964AEE7F397DE65AB {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-22"
      version             = "1.0"

      hash                = "e58ded4d97b3e89176f91f007d82085aed7520ec338f605c0b0b8bce9c94a22a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Digital Online Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "5a:29:21:f8:ff:4e:92:39:64:ae:e7:f3:97:de:65:ab"
      cert_thumbprint     = "49F21B2DDBE9929CCEDB9616E67E9FC29F9B502E"
      cert_valid_from     = "2025-01-22"
      cert_valid_to       = "2026-01-22"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "5a:29:21:f8:ff:4e:92:39:64:ae:e7:f3:97:de:65:ab"
      )
}

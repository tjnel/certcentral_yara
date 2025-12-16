import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_24271B6A45C3D95B6C5BC15C98A84B83 {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-17"
      version             = "1.0"

      hash                = "49c20938fbd31a92a359147b539de76d59be71abf7560801ecc497ca9c8ae809"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ballbusters Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "24:27:1b:6a:45:c3:d9:5b:6c:5b:c1:5c:98:a8:4b:83"
      cert_thumbprint     = "563402AE6879F655A0CA3581F8DE7F8174A6E1F8"
      cert_valid_from     = "2025-04-17"
      cert_valid_to       = "2026-04-17"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Espoo"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "24:27:1b:6a:45:c3:d9:5b:6c:5b:c1:5c:98:a8:4b:83"
      )
}

import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_345A016005DD65DAA24F6C6F86984533 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-26"
      version             = "1.0"

      hash                = "30890f2e20243d6ea815c88de1f9fd0ff9ce4f4f4a0737d4a964e875de74bfba"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTOLIO sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "34:5a:01:60:05:dd:65:da:a2:4f:6c:6f:86:98:45:33"
      cert_thumbprint     = "F395135376359502AC2413C3D832669D608799E9"
      cert_valid_from     = "2025-03-26"
      cert_valid_to       = "2026-03-26"

      country             = "PL"
      state               = "Pomeranian Voivodeship"
      locality            = "Gdynia"
      email               = "???"
      rdn_serial_number   = "0000611933"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "34:5a:01:60:05:dd:65:da:a2:4f:6c:6f:86:98:45:33"
      )
}

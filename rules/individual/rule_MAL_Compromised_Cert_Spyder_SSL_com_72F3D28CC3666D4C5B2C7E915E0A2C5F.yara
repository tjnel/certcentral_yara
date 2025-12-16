import "pe"

rule MAL_Compromised_Cert_Spyder_SSL_com_72F3D28CC3666D4C5B2C7E915E0A2C5F {
   meta:
      description         = "Detects Spyder with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-14"
      version             = "1.0"

      hash                = "2f21da16f2e697a95deb0f89575c1ea2594a78ef5d76a038638c8f1b651d4ae5"
      malware             = "Spyder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Haru Creative Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "72:f3:d2:8c:c3:66:6d:4c:5b:2c:7e:91:5e:0a:2c:5f"
      cert_thumbprint     = "50BF88F2362777F0E3DAC40E51F28DA18B03C059"
      cert_valid_from     = "2025-02-14"
      cert_valid_to       = "2026-02-14"

      country             = "FI"
      state               = "Pirkanmaa"
      locality            = "Tampere"
      email               = "???"
      rdn_serial_number   = "3195241-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "72:f3:d2:8c:c3:66:6d:4c:5b:2c:7e:91:5e:0a:2c:5f"
      )
}

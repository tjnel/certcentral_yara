import "pe"

rule MAL_Compromised_Cert_FakeKeepass_SSL_com_0E012F33DC0BF0BA22432B79611B3238 {
   meta:
      description         = "Detects FakeKeepass with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-20"
      version             = "1.0"

      hash                = "cee5e1fa0175698800cb7832460e877fbe9c76965615ca5dbcbeac55e643fb45"
      malware             = "FakeKeepass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Queenie Francisco"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "0e:01:2f:33:dc:0b:f0:ba:22:43:2b:79:61:1b:32:38"
      cert_thumbprint     = "729E83DFB329F3237905CE0A779C4A914FB06DE4"
      cert_valid_from     = "2025-01-20"
      cert_valid_to       = "2026-01-20"

      country             = "PH"
      state               = "Metro Manila"
      locality            = "Quezon City"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "0e:01:2f:33:dc:0b:f0:ba:22:43:2b:79:61:1b:32:38"
      )
}

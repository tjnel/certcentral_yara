import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GoGetSSL_04AE390F73E5981D11D127316F62BD4B {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GoGetSSL)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-29"
      version             = "1.0"

      hash                = "464b3f10df5c6353b2c84ff3191726de03bcb56642471b0898fb0cb8cffa7fb2"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Johnathan Hunter"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "04:ae:39:0f:73:e5:98:1d:11:d1:27:31:6f:62:bd:4b"
      cert_thumbprint     = "72D3BF7BAFD1F6FB348179C250657EBBDFD6FBD3"
      cert_valid_from     = "2025-07-29"
      cert_valid_to       = "2026-07-28"

      country             = "US"
      state               = "Louisiana"
      locality            = "Marrero"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "04:ae:39:0f:73:e5:98:1d:11:d1:27:31:6f:62:bd:4b"
      )
}

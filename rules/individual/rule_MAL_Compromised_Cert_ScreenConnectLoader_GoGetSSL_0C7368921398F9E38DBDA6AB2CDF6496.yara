import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GoGetSSL_0C7368921398F9E38DBDA6AB2CDF6496 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GoGetSSL)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-24"
      version             = "1.0"

      hash                = "971be21308a52f1eb40954376dd7b2165a52f4b6ade5996e531ca087f44dec78"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "Malware installs ScreenConnect remote access tool."

      signer              = "COD3INC"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "0c:73:68:92:13:98:f9:e3:8d:bd:a6:ab:2c:df:64:96"
      cert_thumbprint     = "DC1BD289538675C832D5166C02041F3A6361FBFC"
      cert_valid_from     = "2025-12-24"
      cert_valid_to       = "2026-12-23"

      country             = "IN"
      state               = "Maharashtra"
      locality            = "MUMBAI"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "0c:73:68:92:13:98:f9:e3:8d:bd:a6:ab:2c:df:64:96"
      )
}

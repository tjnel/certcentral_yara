import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_096EE1A98CE34B25D283F67127F228E7 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-27"
      version             = "1.0"

      hash                = "6c0ba73d26d26441852b731255c5526fc4c445fca2d827018000b29467b2d24e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CREGAN SOFTWARE TESTING LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "09:6e:e1:a9:8c:e3:4b:25:d2:83:f6:71:27:f2:28:e7"
      cert_thumbprint     = "88ED2D3943328F7EB42F58E10568F31897E51785"
      cert_valid_from     = "2024-12-27"
      cert_valid_to       = "2025-12-27"

      country             = "GB"
      state               = "???"
      locality            = "Nottingham"
      email               = "???"
      rdn_serial_number   = "07502570"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "09:6e:e1:a9:8c:e3:4b:25:d2:83:f6:71:27:f2:28:e7"
      )
}

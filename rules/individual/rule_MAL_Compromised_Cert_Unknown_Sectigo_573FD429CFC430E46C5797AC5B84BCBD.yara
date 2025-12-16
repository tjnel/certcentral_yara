import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_573FD429CFC430E46C5797AC5B84BCBD {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-22"
      version             = "1.0"

      hash                = "8ecd3c8c126be7128bf654456d171284f03e4f212c27e1b33f875b8907a7bc65"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "App Interplace LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "57:3f:d4:29:cf:c4:30:e4:6c:57:97:ac:5b:84:bc:bd"
      cert_thumbprint     = "3EBBB02A48F7DB26B708F5E535E8DCE8EFF2CAEA"
      cert_valid_from     = "2025-01-22"
      cert_valid_to       = "2028-01-22"

      country             = "US"
      state               = "Delaware"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "57:3f:d4:29:cf:c4:30:e4:6c:57:97:ac:5b:84:bc:bd"
      )
}

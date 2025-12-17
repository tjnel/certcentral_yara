import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_4E8FD0366C20091348C62BE2F2976CC9 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-03"
      version             = "1.0"

      hash                = "764e4ce9385a20a680e34b80792846340a32e68e733bf50ad8424a896266590d"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tommy Tech LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "4e:8f:d0:36:6c:20:09:13:48:c6:2b:e2:f2:97:6c:c9"
      cert_thumbprint     = "9150D859C1E2041134603E703FBD6650D7D73C12"
      cert_valid_from     = "2023-10-03"
      cert_valid_to       = "2026-10-03"

      country             = "IL"
      state               = "Haifa"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "516196565"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "4e:8f:d0:36:6c:20:09:13:48:c6:2b:e2:f2:97:6c:c9"
      )
}

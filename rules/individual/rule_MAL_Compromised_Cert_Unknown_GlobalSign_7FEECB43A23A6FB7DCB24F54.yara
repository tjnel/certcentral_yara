import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_7FEECB43A23A6FB7DCB24F54 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-01"
      version             = "1.0"

      hash                = "bed2e803af396cf8cc937dd23ce7c198ea33a0718858cdf747293d8375b0a2df"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Eclipse Media Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7f:ee:cb:43:a2:3a:6f:b7:dc:b2:4f:54"
      cert_thumbprint     = "9DBFF2D0B16CB325748A254A9D65A6E885DC252F"
      cert_valid_from     = "2024-05-01"
      cert_valid_to       = "2027-05-02"

      country             = "PA"
      state               = "Panamá"
      locality            = "Ciudad de Panamá"
      email               = "???"
      rdn_serial_number   = "155704432-2-2021"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7f:ee:cb:43:a2:3a:6f:b7:dc:b2:4f:54"
      )
}

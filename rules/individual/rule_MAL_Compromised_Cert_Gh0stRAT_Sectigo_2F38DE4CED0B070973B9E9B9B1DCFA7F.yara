import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_Sectigo_2F38DE4CED0B070973B9E9B9B1DCFA7F {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-17"
      version             = "1.0"

      hash                = "dfa35440cfd1f31f25414561d49989f7e92d87275f2451c0132fc8398ff8e4c9"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Fahad Malik"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "2f:38:de:4c:ed:0b:07:09:73:b9:e9:b9:b1:dc:fa:7f"
      cert_thumbprint     = "D62345CDB71AB6462FE87E9644036DCB2C022B98"
      cert_valid_from     = "2021-05-17"
      cert_valid_to       = "2022-05-17"

      country             = "PK"
      state               = "???"
      locality            = "Multan"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "2f:38:de:4c:ed:0b:07:09:73:b9:e9:b9:b1:dc:fa:7f"
      )
}

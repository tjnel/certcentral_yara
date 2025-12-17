import "pe"

rule MAL_Compromised_Cert_NetWire_Sectigo_2D8CFCF04209DC7F771D8D18E462C35A {
   meta:
      description         = "Detects NetWire with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-09-13"
      version             = "1.0"

      hash                = "af27173ed576215bb06dab3a1526992ee1f8bd358a92d63ad0cfbc0325c70acf"
      malware             = "NetWire"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AA PLUS INVEST d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "2d:8c:fc:f0:42:09:dc:7f:77:1d:8d:18:e4:62:c3:5a"
      cert_thumbprint     = "A9C61E299634BA01E269239DE322FB85E2DA006B"
      cert_valid_from     = "2021-09-13"
      cert_valid_to       = "2022-09-13"

      country             = "SI"
      state               = "Maribor"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "2d:8c:fc:f0:42:09:dc:7f:77:1d:8d:18:e4:62:c3:5a"
      )
}

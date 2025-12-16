import "pe"

rule MAL_Compromised_Cert_NetWire_Sectigo_62205361A758B00572D417CBA014F007 {
   meta:
      description         = "Detects NetWire with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-05-21"
      version             = "1.0"

      hash                = "480e69a305098701404ab144ae64f297e342ca265309dfb7105bbc944aa31cae"
      malware             = "NetWire"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UNITEKH-S, OOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07"
      cert_thumbprint     = "5AEBFEEF4BB5DC7AD5C51001A9CA52A309051D8A"
      cert_valid_from     = "2020-05-21"
      cert_valid_to       = "2021-05-21"

      country             = "RU"
      state               = "Novosibirskaya Obl"
      locality            = "Novosibirsk"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07"
      )
}

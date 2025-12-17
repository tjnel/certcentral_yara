import "pe"

rule MAL_Compromised_Cert_SolarMarker_Sectigo_3821DCACA66A5C5176B921B4D9ED4C97 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-07-22"
      version             = "1.0"

      hash                = "7853518d97bf86211ce0193fcdc8e484615204e97d417386651aa6bbfe686eea"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "BUL D'EVASION"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "38:21:dc:ac:a6:6a:5c:51:76:b9:21:b4:d9:ed:4c:97"
      cert_thumbprint     = "033A6CABA166D80B96E33B1CDD68EDE7487284B6"
      cert_valid_from     = "2022-07-22"
      cert_valid_to       = "2023-07-22"

      country             = "FR"
      state               = "Auvergne-Rhône-Alpes"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "38:21:dc:ac:a6:6a:5c:51:76:b9:21:b4:d9:ed:4c:97"
      )
}

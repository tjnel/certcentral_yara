import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_2782171DABF21DBB7C0A155C38BC1FFB {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-06-17"
      version             = "1.0"

      hash                = "5af99cfc85db7d386c951c76581433cf9bf82eafa775daef93d8bde38a5d6afc"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Bauder Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "27:82:17:1d:ab:f2:1d:bb:7c:0a:15:5c:38:bc:1f:fb"
      cert_thumbprint     = "D83F9E57DA1CE7AC1A6EC5BF2AEDCCE1430E8FFC"
      cert_valid_from     = "2021-06-17"
      cert_valid_to       = "2022-06-17"

      country             = "GB"
      state               = "Norfolk"
      locality            = "Norwich"
      email               = "???"
      rdn_serial_number   = "01466215"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "27:82:17:1d:ab:f2:1d:bb:7c:0a:15:5c:38:bc:1f:fb"
      )
}

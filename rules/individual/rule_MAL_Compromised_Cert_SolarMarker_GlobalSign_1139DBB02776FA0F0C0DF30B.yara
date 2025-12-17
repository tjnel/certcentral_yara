import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_1139DBB02776FA0F0C0DF30B {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-04"
      version             = "1.0"

      hash                = "62cc290842868cf7de7c9e75c150ac58acc33e33cd26f12e4fa614408453c549"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ITM LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign Extended Validation CodeSigning CA - SHA256 - G3"
      cert_serial         = "11:39:db:b0:27:76:fa:0f:0c:0d:f3:0b"
      cert_thumbprint     = "215A9C6D7758F1885051BA63BE51127AF7ECAA41"
      cert_valid_from     = "2020-09-04"
      cert_valid_to       = "2021-09-05"

      country             = "RU"
      state               = "Krasnodar Krai"
      locality            = "Krasnodar"
      email               = "???"
      rdn_serial_number   = "1142311001744"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign Extended Validation CodeSigning CA - SHA256 - G3" and
         sig.serial == "11:39:db:b0:27:76:fa:0f:0c:0d:f3:0b"
      )
}

import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_5A364C4957D93406F76321C2316F42F0 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-08-24"
      version             = "1.0"

      hash                = "4e7f9e963408d0744d58a933d904996d43aa5f065fe12a6b9cbace6a527932a7"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Board Game Bucket Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5a:36:4c:49:57:d9:34:06:f7:63:21:c2:31:6f:42:f0"
      cert_thumbprint     = "2FB8ED066E8457F2D9A32087339D4C95F3DF7BE8"
      cert_valid_from     = "2022-08-24"
      cert_valid_to       = "2023-08-24"

      country             = "GB"
      state               = "Greater London"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "11430692"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5a:36:4c:49:57:d9:34:06:f7:63:21:c2:31:6f:42:f0"
      )
}

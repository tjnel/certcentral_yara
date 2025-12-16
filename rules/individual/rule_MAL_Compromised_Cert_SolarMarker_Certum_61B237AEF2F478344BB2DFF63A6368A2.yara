import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_61B237AEF2F478344BB2DFF63A6368A2 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-20"
      version             = "1.0"

      hash                = "5da219f776810a42d8c8e26989f420ece92e87b6279e3bb39dc9627ad0b7f909"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Crowded Out Limited"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "61:b2:37:ae:f2:f4:78:34:4b:b2:df:f6:3a:63:68:a2"
      cert_thumbprint     = "01A98A25CCDF4A7DE975F10801B0AE0099C9138A"
      cert_valid_from     = "2022-09-20"
      cert_valid_to       = "2023-09-20"

      country             = "GB"
      state               = "???"
      locality            = "Hildenborough"
      email               = "???"
      rdn_serial_number   = "11908098"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "61:b2:37:ae:f2:f4:78:34:4b:b2:df:f6:3a:63:68:a2"
      )
}

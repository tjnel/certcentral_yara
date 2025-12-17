import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_5EBFBF4B22271CE3E174938BBA664980 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-02"
      version             = "1.0"

      hash                = "b10e90ffd7b0bec744d7de5d65e1c71a213aafae0c9fb897ce97c8496725af2b"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "A13 Software Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5e:bf:bf:4b:22:27:1c:e3:e1:74:93:8b:ba:66:49:80"
      cert_thumbprint     = "93D60434FC41BCB357AA842E9BE5D7ACE8A0B0C7"
      cert_valid_from     = "2022-09-02"
      cert_valid_to       = "2023-09-02"

      country             = "GB"
      state               = "Greater London"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "14307326"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5e:bf:bf:4b:22:27:1c:e3:e1:74:93:8b:ba:66:49:80"
      )
}

import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_029331118B3CBFFD93410BCE02AC3211 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-07-20"
      version             = "1.0"

      hash                = "add7cdf9d10a61d354f6235cc5b8576208df03afc67df767687092b6cee66df7"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Lunar Industrial Software, Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "02:93:31:11:8b:3c:bf:fd:93:41:0b:ce:02:ac:32:11"
      cert_thumbprint     = "80485F2DC8DA7855DD624C7124F0AD95A0F7EBCB"
      cert_valid_from     = "2022-07-20"
      cert_valid_to       = "2023-07-18"

      country             = "US"
      state               = "Wyoming"
      locality            = "Cheyenne"
      email               = "???"
      rdn_serial_number   = "2008-000555102"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "02:93:31:11:8b:3c:bf:fd:93:41:0b:ce:02:ac:32:11"
      )
}

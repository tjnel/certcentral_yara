import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0636769AA66BF4317A772F5FE23CE085 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-06-27"
      version             = "1.0"

      hash                = "f1974ba6905ffb380edf9bad7c799b31c4d3668fd80d87691ca885ee18d551dc"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "IDS-Software Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:36:76:9a:a6:6b:f4:31:7a:77:2f:5f:e2:3c:e0:85"
      cert_thumbprint     = "E0391E2E949896F60EA3CC30FC23AB704C16FFE2"
      cert_valid_from     = "2022-06-27"
      cert_valid_to       = "2023-06-23"

      country             = "IE"
      state               = "???"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "694990"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:36:76:9a:a6:6b:f4:31:7a:77:2f:5f:e2:3c:e0:85"
      )
}

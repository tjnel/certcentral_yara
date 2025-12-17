import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0E9D7A2348CE1EB34FF6D61A86244DEE {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-24"
      version             = "1.0"

      hash                = "2d72b1e256c6b483684ff9268be5318a7294490c7f05a07e025f54a4cadd2f2e"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "BizIncorp Online Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0e:9d:7a:23:48:ce:1e:b3:4f:f6:d6:1a:86:24:4d:ee"
      cert_thumbprint     = "EA451EB228001C7EB52B508534956EA09EA12D3E"
      cert_valid_from     = "2022-03-24"
      cert_valid_to       = "2023-04-07"

      country             = "CA"
      state               = "Alberta"
      locality            = "Edmonton"
      email               = "???"
      rdn_serial_number   = "1281288-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0e:9d:7a:23:48:ce:1e:b3:4f:f6:d6:1a:86:24:4d:ee"
      )
}

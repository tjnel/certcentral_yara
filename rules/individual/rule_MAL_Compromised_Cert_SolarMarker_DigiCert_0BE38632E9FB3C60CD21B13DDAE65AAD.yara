import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0BE38632E9FB3C60CD21B13DDAE65AAD {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-08"
      version             = "1.0"

      hash                = "9fcdb329122b918110be82e8040386798f1a0c28ad1d103bf06e5df6ec820aca"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Ameri Mode Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0b:e3:86:32:e9:fb:3c:60:cd:21:b1:3d:da:e6:5a:ad"
      cert_thumbprint     = "F6A5A43F2695A978EF786F0A79E759D5C5DC78F0"
      cert_valid_from     = "2024-05-08"
      cert_valid_to       = "2025-05-07"

      country             = "CA"
      state               = "Quebec"
      locality            = "Montreal"
      email               = "???"
      rdn_serial_number   = "780727-9"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0b:e3:86:32:e9:fb:3c:60:cd:21:b1:3d:da:e6:5a:ad"
      )
}

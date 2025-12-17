import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0D6D1BA122C0E6586352D55D246D07A0 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-06-10"
      version             = "1.0"

      hash                = "6d1a637ee2263dc7918b886a8a1878fb73a000510bc6f42e0c59669487c46e82"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "G & D Consulting, LLC."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:6d:1b:a1:22:c0:e6:58:63:52:d5:5d:24:6d:07:a0"
      cert_thumbprint     = "5000EC2761F1B555F28482A142B4336A2DE8C36E"
      cert_valid_from     = "2022-06-10"
      cert_valid_to       = "2023-05-10"

      country             = "US"
      state               = "Georgia"
      locality            = "Columbus"
      email               = "???"
      rdn_serial_number   = "18040852"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:6d:1b:a1:22:c0:e6:58:63:52:d5:5d:24:6d:07:a0"
      )
}

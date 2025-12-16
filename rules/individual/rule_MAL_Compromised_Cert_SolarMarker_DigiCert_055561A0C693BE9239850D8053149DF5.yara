import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_055561A0C693BE9239850D8053149DF5 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-19"
      version             = "1.0"

      hash                = "057aa4a06395c384a2a9d29f499b410ac1da6fc2c10aa61908eea3e67a32b872"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "TOV \"SELT MOTO\""
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "05:55:61:a0:c6:93:be:92:39:85:0d:80:53:14:9d:f5"
      cert_thumbprint     = "9B4FC6429F8FB28ABFF5EF891153E470D2B6F505"
      cert_valid_from     = "2023-04-19"
      cert_valid_to       = "2024-04-18"

      country             = "UA"
      state               = "???"
      locality            = "Dnipro"
      email               = "???"
      rdn_serial_number   = "45073828"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "05:55:61:a0:c6:93:be:92:39:85:0d:80:53:14:9d:f5"
      )
}

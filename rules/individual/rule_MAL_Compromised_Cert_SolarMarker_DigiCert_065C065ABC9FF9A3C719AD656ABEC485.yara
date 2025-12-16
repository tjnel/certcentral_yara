import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_065C065ABC9FF9A3C719AD656ABEC485 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-06-09"
      version             = "1.0"

      hash                = "08e055a874ff5c2dcd27eb973b991fcbcd20d2ab6e3baa183f004f5f22c4f9e8"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "SijuThomas Consulting Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:5c:06:5a:bc:9f:f9:a3:c7:19:ad:65:6a:be:c4:85"
      cert_thumbprint     = "25248B19256907D8761B890E088C23247009DEB6"
      cert_valid_from     = "2022-06-09"
      cert_valid_to       = "2023-06-01"

      country             = "CA"
      state               = "Ontario"
      locality            = "Brampton"
      email               = "???"
      rdn_serial_number   = "1006125-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:5c:06:5a:bc:9f:f9:a3:c7:19:ad:65:6a:be:c4:85"
      )
}

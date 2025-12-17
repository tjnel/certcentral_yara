import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_04926FF6AAC88D45447E23ADC38D34E5 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-10"
      version             = "1.0"

      hash                = "ab7489ecce8cbd41191d4e63e741d679d95bfb77b01a55285abf65f3337918f8"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Dynamic Digital Marketing Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "04:92:6f:f6:aa:c8:8d:45:44:7e:23:ad:c3:8d:34:e5"
      cert_thumbprint     = "150776149EEBBEAEA7853F5BED7BE6940A1626CC"
      cert_valid_from     = "2022-03-10"
      cert_valid_to       = "2023-03-17"

      country             = "CA"
      state               = "Ontario"
      locality            = "Gloucester"
      email               = "???"
      rdn_serial_number   = "3277735"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "04:92:6f:f6:aa:c8:8d:45:44:7e:23:ad:c3:8d:34:e5"
      )
}

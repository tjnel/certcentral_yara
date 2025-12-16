import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_03AD977571E5079C2AD3846D61CE6E54 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-28"
      version             = "1.0"

      hash                = "96512386ea92612cd3c09c377f6a62e1df7a940ce4e46ca5562d75a1017413c9"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Plus 5 XP Corporation"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "03:ad:97:75:71:e5:07:9c:2a:d3:84:6d:61:ce:6e:54"
      cert_thumbprint     = "DA4A8327B3ED583671F7CE38F615482B4B0A5C15"
      cert_valid_from     = "2024-05-28"
      cert_valid_to       = "2025-05-07"

      country             = "CA"
      state               = "Quebec"
      locality            = "Montreal"
      email               = "???"
      rdn_serial_number   = "1083756-3"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "03:ad:97:75:71:e5:07:9c:2a:d3:84:6d:61:ce:6e:54"
      )
}

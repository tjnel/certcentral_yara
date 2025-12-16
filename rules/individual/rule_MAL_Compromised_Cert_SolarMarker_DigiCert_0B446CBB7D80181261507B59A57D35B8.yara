import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0B446CBB7D80181261507B59A57D35B8 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-07-08"
      version             = "1.0"

      hash                = "0c8d4cfd455bf5f799b4b4bf748eefc7cabe940363fe55dd71f881f7607c3bf3"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "MD Management SARL"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0b:44:6c:bb:7d:80:18:12:61:50:7b:59:a5:7d:35:b8"
      cert_thumbprint     = "2D0B2B9FABF063AD38810FC1191DBA59EE1E86CE"
      cert_valid_from     = "2021-07-08"
      cert_valid_to       = "2022-07-11"

      country             = "BE"
      state               = "???"
      locality            = "Brussels"
      email               = "???"
      rdn_serial_number   = "0769.336.296"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0b:44:6c:bb:7d:80:18:12:61:50:7b:59:a5:7d:35:b8"
      )
}

import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_06FA27A121CC82230C3013EE634B6C62 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-18"
      version             = "1.0"

      hash                = "2f7287a8b0c612801e77de6c2f37e22e0a67579f203a0aaf40095bf6ff70e6ee"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Zimmi Consulting Inc"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:fa:27:a1:21:cc:82:23:0c:30:13:ee:63:4b:6c:62"
      cert_thumbprint     = "BA256F3716A5613B2DDA5F2DBD36ABC9AC321583"
      cert_valid_from     = "2022-02-18"
      cert_valid_to       = "2023-02-13"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "1005078-4"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:fa:27:a1:21:cc:82:23:0c:30:13:ee:63:4b:6c:62"
      )
}

import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_08063F7043D2981C5A9A8E7769875262 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-06-22"
      version             = "1.0"

      hash                = "5e2d71794b574e880880b771fd2011f16a5eb1346b731caacdac0d80bfc0c0a1"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Hillcoe Software Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "08:06:3f:70:43:d2:98:1c:5a:9a:8e:77:69:87:52:62"
      cert_thumbprint     = "5E89FADECABA7EB9582F9DFCAC63B3783BD5FC9D"
      cert_valid_from     = "2022-06-22"
      cert_valid_to       = "2023-06-21"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "1204212-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "08:06:3f:70:43:d2:98:1c:5a:9a:8e:77:69:87:52:62"
      )
}

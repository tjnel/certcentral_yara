import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0DD8B5184BF2BD3342498F8AFCF78FD9 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-08-21"
      version             = "1.0"

      hash                = "b3d5baeef9ba35109bd270f5ec27e15cf691217dd591b29ae83ebd07989af947"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Aero IT ApS"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:d8:b5:18:4b:f2:bd:33:42:49:8f:8a:fc:f7:8f:d9"
      cert_thumbprint     = "13F62A113F36D508594FE4ECC4C66B377AF5362B"
      cert_valid_from     = "2021-08-21"
      cert_valid_to       = "2022-08-19"

      country             = "DK"
      state               = "???"
      locality            = "Hørsholm"
      email               = "???"
      rdn_serial_number   = "42586781"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:d8:b5:18:4b:f2:bd:33:42:49:8f:8a:fc:f7:8f:d9"
      )
}

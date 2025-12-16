import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_DigiCert_08FA393DD84ABD186267BF979A4F2690 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-17"
      version             = "1.0"

      hash                = "284958ad33d336ba2560d40126bf2927d1be0533a5ff3638f3ddab16f31c79c8"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NEKO KITTYS LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "08:fa:39:3d:d8:4a:bd:18:62:67:bf:97:9a:4f:26:90"
      cert_thumbprint     = "79BD2E8609049FA9AD6B49B7E9C020C19708E54B"
      cert_valid_from     = "2025-07-17"
      cert_valid_to       = "2026-07-16"

      country             = "US"
      state               = "Wyoming"
      locality            = "Sheridan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "08:fa:39:3d:d8:4a:bd:18:62:67:bf:97:9a:4f:26:90"
      )
}

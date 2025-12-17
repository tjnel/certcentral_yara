import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_0732E2A94E3F6F85A26DB09CA03FC48F {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-22"
      version             = "1.0"

      hash                = "0c58175d22b45fd06cfed62d7a9a33b1f13c049427a83904a04db9810c44eb5a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "北京华网智讯软件有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "07:32:e2:a9:4e:3f:6f:85:a2:6d:b0:9c:a0:3f:c4:8f"
      cert_thumbprint     = "0D599A8B43DB2A7C65D68E5696F7649CEEA5C60C"
      cert_valid_from     = "2024-10-22"
      cert_valid_to       = "2025-10-21"

      country             = "CN"
      state               = "北京市"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "07:32:e2:a9:4e:3f:6f:85:a2:6d:b0:9c:a0:3f:c4:8f"
      )
}

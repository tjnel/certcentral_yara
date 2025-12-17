import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_01FD6F6E1223421F0260949FCEB36201 {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-19"
      version             = "1.0"

      hash                = "18c616aad862dcd00837362a8f3c3eb2419b3a01721675ffda8b22461d37eb52"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JUST OKAY LIMITED"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "01:fd:6f:6e:12:23:42:1f:02:60:94:9f:ce:b3:62:01"
      cert_thumbprint     = "E39BE0CB221EE285BE0302F2578DE32457DF2FA0"
      cert_valid_from     = "2024-12-19"
      cert_valid_to       = "2025-12-18"

      country             = "HK"
      state               = "???"
      locality            = "Kowloon"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "01:fd:6f:6e:12:23:42:1f:02:60:94:9f:ce:b3:62:01"
      )
}

import "pe"

rule MAL_Compromised_Cert_Unknown_Fake_Browser_update_DigiCert_0C0999179801B46B92911B8B671018A8 {
   meta:
      description         = "Detects Unknown, Fake Browser update with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-22"
      version             = "1.0"

      hash                = "22014e2d31197dddc2c451ed475aede3d21ca99784973bdcfd9c3a7d9aaa1999"
      malware             = "Unknown, Fake Browser update"
      malware_type        = "Initial access tool"
      malware_notes       = "File was disguised as a browser update but also used Adobe logos. The full behavior isn't understood at this time."

      signer              = "山西荣升源科贸有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA256 2021 CA1"
      cert_serial         = "0c:09:99:17:98:01:b4:6b:92:91:1b:8b:67:10:18:a8"
      cert_thumbprint     = "FF6B134559A6D51E99A294242748B05D4222BCF8"
      cert_valid_from     = "2025-05-22"
      cert_valid_to       = "2028-08-17"

      country             = "CN"
      state               = "山西省"
      locality            = "太原市"
      email               = "???"
      rdn_serial_number   = "91140105MA0LK0WH8B"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA256 2021 CA1" and
         sig.serial == "0c:09:99:17:98:01:b4:6b:92:91:1b:8b:67:10:18:a8"
      )
}

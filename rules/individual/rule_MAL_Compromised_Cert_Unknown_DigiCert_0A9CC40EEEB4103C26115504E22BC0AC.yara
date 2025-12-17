import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_0A9CC40EEEB4103C26115504E22BC0AC {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-01-25"
      version             = "1.0"

      hash                = "a8af10f68d566fb3f7de1f27e354b70cde80286ca33eb4aaf3e9e048591870cb"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Beijing Jinwanwei Technology Co., Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0a:9c:c4:0e:ee:b4:10:3c:26:11:55:04:e2:2b:c0:ac"
      cert_thumbprint     = "A0A23DEAEF32755A1660CD784EAF2C72AE3D6633"
      cert_valid_from     = "2022-01-25"
      cert_valid_to       = "2025-02-19"

      country             = "CN"
      state               = "beijing"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0a:9c:c4:0e:ee:b4:10:3c:26:11:55:04:e2:2b:c0:ac"
      )
}

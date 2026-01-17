import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_DigiCert_029C936B150B5C3588B661A870BEB57B {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-08"
      version             = "1.0"

      hash                = "35e2c85aace30e80ac51e3aecc5a9652b2a514c6d6e90e96b9b9f3b6bea06835"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "STEWART DIXON AQUATIC SERVICES LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "02:9c:93:6b:15:0b:5c:35:88:b6:61:a8:70:be:b5:7b"
      cert_thumbprint     = "BEB331DE367D2478EF638FD0E29C55E037E7AF2B"
      cert_valid_from     = "2026-01-08"
      cert_valid_to       = "2029-01-10"

      country             = "US"
      state               = "Indiana"
      locality            = "GREENWOOD"
      email               = "???"
      rdn_serial_number   = "2012031900678"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "02:9c:93:6b:15:0b:5c:35:88:b6:61:a8:70:be:b5:7b"
      )
}

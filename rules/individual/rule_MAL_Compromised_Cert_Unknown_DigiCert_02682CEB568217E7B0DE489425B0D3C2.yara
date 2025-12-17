import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_02682CEB568217E7B0DE489425B0D3C2 {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-19"
      version             = "1.0"

      hash                = "e115cd3f7f9fb0d34d8ddb909da419a93ff441fd0c6a787afe9c130b03f6ff5e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "飛原數位科技有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "02:68:2c:eb:56:82:17:e7:b0:de:48:94:25:b0:d3:c2"
      cert_thumbprint     = "4D736329D5A5F9E53180EAA03D0C3621539F082D"
      cert_valid_from     = "2024-08-19"
      cert_valid_to       = "2027-08-21"

      country             = "TW"
      state               = "桃園市"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "52881336"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "02:68:2c:eb:56:82:17:e7:b0:de:48:94:25:b0:d3:c2"
      )
}

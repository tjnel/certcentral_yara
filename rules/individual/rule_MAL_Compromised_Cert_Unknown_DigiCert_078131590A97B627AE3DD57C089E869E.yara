import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_078131590A97B627AE3DD57C089E869E {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-24"
      version             = "1.0"

      hash                = "510e2f0999c2d7381fc22ee4c4bf72e0ab1bbe779e01a81095690b1bdc633ece"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Enviaolo LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "07:81:31:59:0a:97:b6:27:ae:3d:d5:7c:08:9e:86:9e"
      cert_thumbprint     = "2CAD5366B72AA3FF63587579238D5DAF9EEC147B"
      cert_valid_from     = "2024-07-24"
      cert_valid_to       = "2025-07-23"

      country             = "US"
      state               = "Oklahoma"
      locality            = "Edmond"
      email               = "???"
      rdn_serial_number   = "3513614123"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "07:81:31:59:0a:97:b6:27:ae:3d:d5:7c:08:9e:86:9e"
      )
}

import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_0BC0F18DA36702E302DB170D91DC9202 {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-11-24"
      version             = "1.0"

      hash                = "173811d2b7ef473b502fac29d92c65ee2a04810aa1f9722b9dd6eeb659218531"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Foresee Consulting Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0b:c0:f1:8d:a3:67:02:e3:02:db:17:0d:91:dc:92:02"
      cert_thumbprint     = "ACC694AF50E6A4AF44820B0B2D2A06615FD2F73F"
      cert_valid_from     = "2021-11-24"
      cert_valid_to       = "2022-11-23"

      country             = "CA"
      state               = "Ontario"
      locality            = "North York"
      email               = "???"
      rdn_serial_number   = "1004913-1"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0b:c0:f1:8d:a3:67:02:e3:02:db:17:0d:91:dc:92:02"
      )
}

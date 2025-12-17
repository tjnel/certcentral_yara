import "pe"

rule MAL_Compromised_Cert_FakePDFBrowserHijacker_DigiCert_037FAF39D5EFECFEEDC2950F625EAB0E {
   meta:
      description         = "Detects FakePDFBrowserHijacker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-07"
      version             = "1.0"

      hash                = "7c5004c9d3ed4325c547ec0127d59205529f4574444a9e74dc108b0783d6e392"
      malware             = "FakePDFBrowserHijacker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Flooencia Media LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "03:7f:af:39:d5:ef:ec:fe:ed:c2:95:0f:62:5e:ab:0e"
      cert_thumbprint     = "BC3815D8174DDBCAD1C44DA0CD818BB4E1698D21"
      cert_valid_from     = "2025-07-07"
      cert_valid_to       = "2028-07-06"

      country             = "US"
      state               = "Wyoming"
      locality            = "Sheridan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "03:7f:af:39:d5:ef:ec:fe:ed:c2:95:0f:62:5e:ab:0e"
      )
}

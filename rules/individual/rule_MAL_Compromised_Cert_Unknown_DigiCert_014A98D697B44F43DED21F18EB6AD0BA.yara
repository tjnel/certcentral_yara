import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_014A98D697B44F43DED21F18EB6AD0BA {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-13"
      version             = "1.0"

      hash                = "ab9bd45d65800bd2a72124f0188face3b8d79abd5d3e41d95a29383f851f9381"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hillcoe Software Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "01:4a:98:d6:97:b4:4f:43:de:d2:1f:18:eb:6a:d0:ba"
      cert_thumbprint     = "4DB86D367D001BE757047F35796C8A5926A7C2E5"
      cert_valid_from     = "2020-11-13"
      cert_valid_to       = "2021-11-14"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "1204212-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "01:4a:98:d6:97:b4:4f:43:de:d2:1f:18:eb:6a:d0:ba"
      )
}

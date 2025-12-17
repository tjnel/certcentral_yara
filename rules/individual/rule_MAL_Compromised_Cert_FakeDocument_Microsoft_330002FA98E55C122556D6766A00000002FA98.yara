import "pe"

rule MAL_Compromised_Cert_FakeDocument_Microsoft_330002FA98E55C122556D6766A00000002FA98 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "558e5d48cc2ae8e2daf2027e3edd09c3417a621d435bee086807df61570e6d3d"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:fa:98:e5:5c:12:25:56:d6:76:6a:00:00:00:02:fa:98"
      cert_thumbprint     = "E50D86E7DB8CB8F184BC59297CD59D6E8B8FC465"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2025-05-24"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:fa:98:e5:5c:12:25:56:d6:76:6a:00:00:00:02:fa:98"
      )
}

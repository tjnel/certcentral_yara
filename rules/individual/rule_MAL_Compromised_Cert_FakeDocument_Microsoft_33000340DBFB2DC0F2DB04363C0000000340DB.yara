import "pe"

rule MAL_Compromised_Cert_FakeDocument_Microsoft_33000340DBFB2DC0F2DB04363C0000000340DB {
   meta:
      description         = "Detects FakeDocument with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-11"
      version             = "1.0"

      hash                = "38536fb62f74274cf1ddd77ea40b4187a590235099936cf6d0504727c34cd796"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:03:40:db:fb:2d:c0:f2:db:04:36:3c:00:00:00:03:40:db"
      cert_thumbprint     = "CAD67D0A64477FDC31BDEB80F8714E2686F547D1"
      cert_valid_from     = "2025-06-11"
      cert_valid_to       = "2025-06-14"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:03:40:db:fb:2d:c0:f2:db:04:36:3c:00:00:00:03:40:db"
      )
}

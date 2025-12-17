import "pe"

rule MAL_Compromised_Cert_FakeInstallers_Microsoft_3300055C80AFCFC210CF3436B7000000055C80 {
   meta:
      description         = "Detects FakeInstallers with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-09"
      version             = "1.0"

      hash                = "ba347d3e163372f5b036a44dac79b50df5f878c4c4f62319a190ce27dccc2f57"
      malware             = "FakeInstallers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "56 SQUARED PARTNERS LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:5c:80:af:cf:c2:10:cf:34:36:b7:00:00:00:05:5c:80"
      cert_thumbprint     = "2111E7A8412531B96ACE76E1ED73B238D759779B"
      cert_valid_from     = "2025-09-09"
      cert_valid_to       = "2025-09-12"

      country             = "US"
      state               = "New York"
      locality            = "New York"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:5c:80:af:cf:c2:10:cf:34:36:b7:00:00:00:05:5c:80"
      )
}

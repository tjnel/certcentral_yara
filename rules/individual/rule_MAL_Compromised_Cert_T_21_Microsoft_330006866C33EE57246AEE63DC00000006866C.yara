import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330006866C33EE57246AEE63DC00000006866C {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-14"
      version             = "1.0"

      hash                = "01c1c9287cc4479266bf5e0ea61c39ab0184a015e147b1ead54bb2c1b3e96e58"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex Meeting Launchers spread by a traffer group, involved in a malware campaign around a compromised LinkedIn company account, targeting job-seekers with fake crypto-related job offers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:86:6c:33:ee:57:24:6a:ee:63:dc:00:00:00:06:86:6c"
      cert_thumbprint     = "676916D1CFC094862D83C969C81DAD3CADB86785"
      cert_valid_from     = "2025-12-14"
      cert_valid_to       = "2025-12-17"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:86:6c:33:ee:57:24:6a:ee:63:dc:00:00:00:06:86:6c"
      )
}

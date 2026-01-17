import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330006C90E1E4B1032EB97B8CF00000006C90E {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-05"
      version             = "1.0"

      hash                = "c1749ecadfe876c98b403b86db0004ee3201620cf0c070cdf7293baff6ce1367"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex Meeting Launchers spread by a traffer group, involved in a malware campaign around a compromised LinkedIn company account, targeting job-seekers with fake crypto-related job offers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:c9:0e:1e:4b:10:32:eb:97:b8:cf:00:00:00:06:c9:0e"
      cert_thumbprint     = "B814580D5DBF1AC0326AAEAF5CBC9389FB32F488"
      cert_valid_from     = "2026-01-05"
      cert_valid_to       = "2026-01-08"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:c9:0e:1e:4b:10:32:eb:97:b8:cf:00:00:00:06:c9:0e"
      )
}

import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330006D18A37899D7C1808ED4D00000006D18A {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-07"
      version             = "1.0"

      hash                = "10b419bea17f6046d86b60b73561469714f5ba93a9e6efaa9607efe50d83f543"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex Meeting Launchers spread by a traffer group, involved in a malware campaign around a compromised LinkedIn company account, targeting job-seekers with fake crypto-related job offers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:d1:8a:37:89:9d:7c:18:08:ed:4d:00:00:00:06:d1:8a"
      cert_thumbprint     = "A3FE677A0A943E92F73611C1B72021E56B70A765"
      cert_valid_from     = "2026-01-07"
      cert_valid_to       = "2026-01-10"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:d1:8a:37:89:9d:7c:18:08:ed:4d:00:00:00:06:d1:8a"
      )
}

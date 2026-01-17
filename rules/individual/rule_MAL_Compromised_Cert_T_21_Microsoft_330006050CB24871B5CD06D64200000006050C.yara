import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330006050CB24871B5CD06D64200000006050C {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-27"
      version             = "1.0"

      hash                = "0238ae476ae6283dfa4f55169aba66e5bd8352f504bde249d8550234a0dadf9b"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex Meeting Launchers spread by a traffer group, involved in a malware campaign around a compromised LinkedIn company account, targeting job-seekers with fake crypto-related job offers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:06:05:0c:b2:48:71:b5:cd:06:d6:42:00:00:00:06:05:0c"
      cert_thumbprint     = "275CF8C328D8FB242E1C75E72721BD8C25A485E2"
      cert_valid_from     = "2025-12-27"
      cert_valid_to       = "2025-12-30"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:06:05:0c:b2:48:71:b5:cd:06:d6:42:00:00:00:06:05:0c"
      )
}

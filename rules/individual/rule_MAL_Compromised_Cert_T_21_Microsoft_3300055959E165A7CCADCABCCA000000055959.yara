import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_3300055959E165A7CCADCABCCA000000055959 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-18"
      version             = "1.0"

      hash                = "816d26e9aa530ad4b82bee56502bb158ab899b55b7056ef7f728d0def8f6432c"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex Meeting Launchers spread by a traffer group, involved in a malware campaign around a compromised LinkedIn company account, targeting job-seekers with fake crypto-related job offers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:59:59:e1:65:a7:cc:ad:ca:bc:ca:00:00:00:05:59:59"
      cert_thumbprint     = "C379089F05BFAF060D83491956BCF59896591BF8"
      cert_valid_from     = "2025-11-18"
      cert_valid_to       = "2025-11-21"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:59:59:e1:65:a7:cc:ad:ca:bc:ca:00:00:00:05:59:59"
      )
}

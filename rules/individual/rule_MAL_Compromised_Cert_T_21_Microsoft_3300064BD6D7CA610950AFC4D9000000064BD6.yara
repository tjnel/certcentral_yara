import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_3300064BD6D7CA610950AFC4D9000000064BD6 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-12"
      version             = "1.0"

      hash                = "5c07a238b8f0a4f13309663e52bb900d8cfbd7fb2a4ddaff9ab6197ee89e1c34"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex Meeting Launchers spread by a traffer group, involved in a malware campaign around a compromised LinkedIn company account, targeting job-seekers with fake crypto-related job offers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:4b:d6:d7:ca:61:09:50:af:c4:d9:00:00:00:06:4b:d6"
      cert_thumbprint     = "60FF9C7541D3DFA2F35A327C16E5EF1AE2A93765"
      cert_valid_from     = "2025-11-12"
      cert_valid_to       = "2025-11-15"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:4b:d6:d7:ca:61:09:50:af:c4:d9:00:00:00:06:4b:d6"
      )
}

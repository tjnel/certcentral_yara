import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Microsoft_3300066EACA3015D01FAFC05C3000000066EAC {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-08"
      version             = "1.0"

      hash                = "b0383b31ab663412a3a50e9a19032942a4819320055577f583b0831760a8cf12"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Martines Palmeiro Construction, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:6e:ac:a3:01:5d:01:fa:fc:05:c3:00:00:00:06:6e:ac"
      cert_thumbprint     = "86F61E8A4342E1EF55DDDFFD14469CCC68D40D9B"
      cert_valid_from     = "2025-12-08"
      cert_valid_to       = "2025-12-11"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:6e:ac:a3:01:5d:01:fa:fc:05:c3:00:00:00:06:6e:ac"
      )
}

import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Microsoft_33000578F93468681279E2CFDE0000000578F9 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-27"
      version             = "1.0"

      hash                = "1e92331008dcbb8231fb750ec4d6dbda4d5b6c16e9c4ef302e261b06a9d19929"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GROUPE PROMO-STAFF RTM INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:78:f9:34:68:68:12:79:e2:cf:de:00:00:00:05:78:f9"
      cert_thumbprint     = "E75CE4F6D588555B946CF3066983990C57B3E9F2"
      cert_valid_from     = "2025-11-27"
      cert_valid_to       = "2025-11-30"

      country             = "CA"
      state               = "Québec"
      locality            = "Saint-Philippe"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:78:f9:34:68:68:12:79:e2:cf:de:00:00:00:05:78:f9"
      )
}

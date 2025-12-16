import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Microsoft_3300058C942C910D349BCEE8B2000000058C94 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-02"
      version             = "1.0"

      hash                = "e9c5c6132f2d222ce4f76ff1bf59735f6c527b2e44b8fea4b4275eebfaeaa4e2"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GROUPE PROMO-STAFF RTM INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:8c:94:2c:91:0d:34:9b:ce:e8:b2:00:00:00:05:8c:94"
      cert_thumbprint     = "1BD24A8E138EEBF3CECF87893B0852AD472E7B37"
      cert_valid_from     = "2025-12-02"
      cert_valid_to       = "2025-12-05"

      country             = "CA"
      state               = "Québec"
      locality            = "Saint-Philippe"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:8c:94:2c:91:0d:34:9b:ce:e8:b2:00:00:00:05:8c:94"
      )
}

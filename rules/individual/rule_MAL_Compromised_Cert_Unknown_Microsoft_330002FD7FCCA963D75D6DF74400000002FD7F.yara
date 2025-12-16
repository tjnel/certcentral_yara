import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330002FD7FCCA963D75D6DF74400000002FD7F {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-13"
      version             = "1.0"

      hash                = "eddc26773927d95ab78778a259279e668f52710844f7e3eb4fbdffb5552dc4f1"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TEAM PLAYER SOLUTION LTD"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:02:fd:7f:cc:a9:63:d7:5d:6d:f7:44:00:00:00:02:fd:7f"
      cert_thumbprint     = "78400E93B1496BE07098BF42E6B3E17C63D3C2DC"
      cert_valid_from     = "2025-03-13"
      cert_valid_to       = "2025-03-16"

      country             = "GB"
      state               = "???"
      locality            = "Huntingdon"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:02:fd:7f:cc:a9:63:d7:5d:6d:f7:44:00:00:00:02:fd:7f"
      )
}

import "pe"

rule MAL_Compromised_Cert_HijackLoader_Microsoft_330003033B96D04AB9ED3A8D9F00000003033B {
   meta:
      description         = "Detects HijackLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-26"
      version             = "1.0"

      hash                = "1da6fb17f4c9d8b5e5fa54cc2f17ef038cd2be1fae73d16b6805567f952d0312"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NIGHT OWL CREATIVE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:03:03:3b:96:d0:4a:b9:ed:3a:8d:9f:00:00:00:03:03:3b"
      cert_thumbprint     = "26C9637E1FAE5348AA58121C7AB3D2487F399B7E"
      cert_valid_from     = "2025-05-26"
      cert_valid_to       = "2025-05-29"

      country             = "US"
      state               = "New York"
      locality            = "New York"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:03:03:3b:96:d0:4a:b9:ed:3a:8d:9f:00:00:00:03:03:3b"
      )
}

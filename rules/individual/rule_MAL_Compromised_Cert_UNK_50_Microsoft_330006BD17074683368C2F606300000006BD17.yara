import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330006BD17074683368C2F606300000006BD17 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-16"
      version             = "1.0"

      hash                = "6fd3424fda119628855ed5f1efc14fc619e5eff3e229d483185e114da4c2509f"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Next-Gen Supplements Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:bd:17:07:46:83:36:8c:2f:60:63:00:00:00:06:bd:17"
      cert_thumbprint     = "B1DFF48E7E45813C31857538E171803893D1F377"
      cert_valid_from     = "2025-12-16"
      cert_valid_to       = "2025-12-19"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:bd:17:07:46:83:36:8c:2f:60:63:00:00:00:06:bd:17"
      )
}

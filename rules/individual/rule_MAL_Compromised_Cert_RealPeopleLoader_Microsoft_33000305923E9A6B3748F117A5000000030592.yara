import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_Microsoft_33000305923E9A6B3748F117A5000000030592 {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-29"
      version             = "1.0"

      hash                = "5245b70201643b135c53e7dd19a44f2b3d84ff7bb0e3a3ab3c300f59aeda7297"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INITIATIVE PARTNERS GROUP, LLC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:03:05:92:3e:9a:6b:37:48:f1:17:a5:00:00:00:03:05:92"
      cert_thumbprint     = "50CFC1828E31158D5317BAED4F246D883725C087"
      cert_valid_from     = "2025-05-29"
      cert_valid_to       = "2025-06-01"

      country             = "US"
      state               = "Arizona"
      locality            = "Waddell"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:03:05:92:3e:9a:6b:37:48:f1:17:a5:00:00:00:03:05:92"
      )
}

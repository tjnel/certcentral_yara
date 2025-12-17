import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005C28FC1E398D5899CAFC500000005C28F {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-15"
      version             = "1.0"

      hash                = "559ebdf59f0eaa0f17bcb82750df2d8376020308fe4c89cbe23bcd159cd93a11"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Next-Gen Supplements Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:c2:8f:c1:e3:98:d5:89:9c:af:c5:00:00:00:05:c2:8f"
      cert_thumbprint     = "89812B1AC6AC642AD2E2DF529BAC86A2B340696C"
      cert_valid_from     = "2025-12-15"
      cert_valid_to       = "2025-12-18"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:c2:8f:c1:e3:98:d5:89:9c:af:c5:00:00:00:05:c2:8f"
      )
}

import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_3300068281A2EB372E8FC4A340000000068281 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-01"
      version             = "1.0"

      hash                = "28e52510f4798285b97afc894902d66ee02366b3e7fddd49dbee600bc1fbd16f"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex Meeting Launchers spread by a traffer group, involved in a malware campaign around a compromised LinkedIn company account, targeting job-seekers with fake crypto-related job offers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:82:81:a2:eb:37:2e:8f:c4:a3:40:00:00:00:06:82:81"
      cert_thumbprint     = "97D4734EFAC5BF08DADA67876393F84347F1C40B"
      cert_valid_from     = "2025-12-01"
      cert_valid_to       = "2025-12-04"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:82:81:a2:eb:37:2e:8f:c4:a3:40:00:00:00:06:82:81"
      )
}

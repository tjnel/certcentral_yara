import "pe"

rule MAL_Compromised_Cert_FakeAdvancedIPScanner_GlobalSign_5C1C54F72BCC4DB6079023BA {
   meta:
      description         = "Detects FakeAdvancedIPScanner with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-20"
      version             = "1.0"

      hash                = "fb38ae3d1d24075b2bf4ec2bf94343a4c136a77ddd7758775808d134e6ec7f40"
      malware             = "FakeAdvancedIPScanner"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NOMAC LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5c:1c:54:f7:2b:cc:4d:b6:07:90:23:ba"
      cert_thumbprint     = "2C28CC8AFC87E5B059623D8F655DFAA5D1E0274B"
      cert_valid_from     = "2025-08-20"
      cert_valid_to       = "2026-05-20"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5c:1c:54:f7:2b:cc:4d:b6:07:90:23:ba"
      )
}

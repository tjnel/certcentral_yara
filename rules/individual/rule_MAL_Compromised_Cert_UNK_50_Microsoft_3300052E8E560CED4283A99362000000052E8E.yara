import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300052E8E560CED4283A99362000000052E8E {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-08"
      version             = "1.0"

      hash                = "87874daf50126287e8127bf27f9d69c79bf260594324b12ff1cda393df77dea8"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "DIGI-FUTURE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:2e:8e:56:0c:ed:42:83:a9:93:62:00:00:00:05:2e:8e"
      cert_thumbprint     = "6EC8D8698AB8AA9869E0FEDED2EA167BAFDEDB1B"
      cert_valid_from     = "2025-11-08"
      cert_valid_to       = "2025-11-11"

      country             = "CA"
      state               = "Ontario"
      locality            = "OSHAWA"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:2e:8e:56:0c:ed:42:83:a9:93:62:00:00:00:05:2e:8e"
      )
}

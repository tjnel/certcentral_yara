import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300052571A94F9EB520095835000000052571 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-24"
      version             = "1.0"

      hash                = "9b53444640115a6ee3eca9da396a65bf3bbb59d565a849ab014a011445136af1"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "OTHENTIKA VOYAGE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:25:71:a9:4f:9e:b5:20:09:58:35:00:00:00:05:25:71"
      cert_thumbprint     = "225336777EE8F95AE4DB293A090AF72CC8FCCEFF"
      cert_valid_from     = "2025-08-24"
      cert_valid_to       = "2025-08-27"

      country             = "CA"
      state               = "Québec"
      locality            = "Saint-Bruno-de-Montarville"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:25:71:a9:4f:9e:b5:20:09:58:35:00:00:00:05:25:71"
      )
}

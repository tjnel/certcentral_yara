import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300042A880AF0AFCEF7498CA3000000042A88 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-29"
      version             = "1.0"

      hash                = "f8abde1581a8686dedab6c5de941fd344af5dbc501709832ffceafd968c5c392"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "OTHENTIKA VOYAGE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:04:2a:88:0a:f0:af:ce:f7:49:8c:a3:00:00:00:04:2a:88"
      cert_thumbprint     = "149F587D46EB743E0965EC1292F260A4B0DD60B3"
      cert_valid_from     = "2025-08-29"
      cert_valid_to       = "2025-09-01"

      country             = "CA"
      state               = "Québec"
      locality            = "Saint-Bruno-de-Montarville"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:04:2a:88:0a:f0:af:ce:f7:49:8c:a3:00:00:00:04:2a:88"
      )
}

import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330004F5200F8DFBA556AFDD5800000004F520 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-22"
      version             = "1.0"

      hash                = "20b82125c723e607546cf07356a86cdc40b079320f6f18e21a1a4ad52df86c45"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "OTHENTIKA VOYAGE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:04:f5:20:0f:8d:fb:a5:56:af:dd:58:00:00:00:04:f5:20"
      cert_thumbprint     = "5EEFFDD7BAD01107A67010B1913A1A838EFF895C"
      cert_valid_from     = "2025-08-22"
      cert_valid_to       = "2025-08-25"

      country             = "CA"
      state               = "Québec"
      locality            = "Saint-Bruno-de-Montarville"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:04:f5:20:0f:8d:fb:a5:56:af:dd:58:00:00:00:04:f5:20"
      )
}

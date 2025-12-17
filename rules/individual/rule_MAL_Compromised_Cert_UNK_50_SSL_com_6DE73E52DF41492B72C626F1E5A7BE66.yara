import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_6DE73E52DF41492B72C626F1E5A7BE66 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-18"
      version             = "1.0"

      hash                = "2cbd48a458b1f09c0b5e9fd197d24f668069dee0c2a94c45497dc5f2d9260d65"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "CORTEX"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6d:e7:3e:52:df:41:49:2b:72:c6:26:f1:e5:a7:be:66"
      cert_thumbprint     = "16BFDA0CE795E2651CC94CB166D2B50313682B42"
      cert_valid_from     = "2025-07-18"
      cert_valid_to       = "2026-07-18"

      country             = "BE"
      state               = "East Flanders"
      locality            = "Lochristi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6d:e7:3e:52:df:41:49:2b:72:c6:26:f1:e5:a7:be:66"
      )
}

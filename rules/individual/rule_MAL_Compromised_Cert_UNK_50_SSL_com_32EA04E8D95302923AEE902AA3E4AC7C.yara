import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_32EA04E8D95302923AEE902AA3E4AC7C {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-05"
      version             = "1.0"

      hash                = "c879cdd5c78adddcda4f5cc6ab0878ae1511f5275bfec81a2dd6be14b0ce4c6d"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Netcoder Software Development Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "32:ea:04:e8:d9:53:02:92:3a:ee:90:2a:a3:e4:ac:7c"
      cert_thumbprint     = "0DDD59EDF92361486EA1A53D96BE36517B049E83"
      cert_valid_from     = "2025-09-05"
      cert_valid_to       = "2026-09-05"

      country             = "CA"
      state               = "Quebec"
      locality            = "Montréal"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "32:ea:04:e8:d9:53:02:92:3a:ee:90:2a:a3:e4:ac:7c"
      )
}

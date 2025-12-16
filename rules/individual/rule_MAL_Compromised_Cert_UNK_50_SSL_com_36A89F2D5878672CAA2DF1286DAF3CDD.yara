import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_36A89F2D5878672CAA2DF1286DAF3CDD {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-12"
      version             = "1.0"

      hash                = "3ad1c019bc45bac84fecd0cf6c66d88792aab73acb25a7bb3ee841646fec167b"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Chengdu Chenxi Mining Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "36:a8:9f:2d:58:78:67:2c:aa:2d:f1:28:6d:af:3c:dd"
      cert_thumbprint     = "6f99b34a0f0cf7d9246a5bbb820ddf9877071ef424452cbdfa65d4afe3b2084e"
      cert_valid_from     = "2024-10-12"
      cert_valid_to       = "2025-10-12"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100MA6AEKLP62"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "36:a8:9f:2d:58:78:67:2c:aa:2d:f1:28:6d:af:3c:dd"
      )
}

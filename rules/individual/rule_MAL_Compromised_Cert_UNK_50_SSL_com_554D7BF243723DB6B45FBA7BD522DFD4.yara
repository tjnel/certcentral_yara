import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_554D7BF243723DB6B45FBA7BD522DFD4 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-10"
      version             = "1.0"

      hash                = "431c1422d417b82670cb32cded474ff956013ed6524f1e5653dbc4995e1930d2"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Hebei EWIN Enterprise Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "55:4d:7b:f2:43:72:3d:b6:b4:5f:ba:7b:d5:22:df:d4"
      cert_thumbprint     = "88ACB5F326D7D19A2EB879C1314EB88B22E94215"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2026-06-09"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "911301007524461955"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "55:4d:7b:f2:43:72:3d:b6:b4:5f:ba:7b:d5:22:df:d4"
      )
}

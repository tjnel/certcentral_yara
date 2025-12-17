import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_2397973243352DA3ED055BC1D9A5CFC6 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-30"
      version             = "1.0"

      hash                = "b864b1fbb0fbcd561fbfce5462b43b8a49b5f1011867da509418b8068dd45c54"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Market Intelligence Systems (MIS) B.V."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "23:97:97:32:43:35:2d:a3:ed:05:5b:c1:d9:a5:cf:c6"
      cert_thumbprint     = "E2C140D2A11A8B08E2A87E1CA9C08D88158FA45B"
      cert_valid_from     = "2025-07-30"
      cert_valid_to       = "2026-07-30"

      country             = "NL"
      state               = "South Holland"
      locality            = "Dordrecht"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "23:97:97:32:43:35:2d:a3:ed:05:5b:c1:d9:a5:cf:c6"
      )
}

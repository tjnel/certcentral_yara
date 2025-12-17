import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_24D8130F15678AFE57E0A7790D170380 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-19"
      version             = "1.0"

      hash                = "927858756908b6991e7855871b54472eac676b420772048319b0d90f2599714e"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Questor IT Consulting Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "24:d8:13:0f:15:67:8a:fe:57:e0:a7:79:0d:17:03:80"
      cert_thumbprint     = "B67CE96127ECB75785E2F281C23E4681FFB0F915"
      cert_valid_from     = "2025-09-19"
      cert_valid_to       = "2026-09-19"

      country             = "CA"
      state               = "Quebec"
      locality            = "Gatineau"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "24:d8:13:0f:15:67:8a:fe:57:e0:a7:79:0d:17:03:80"
      )
}

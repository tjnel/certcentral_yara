import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_11B1D2BBDD832C2E560EEAA79A0D75C0 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-28"
      version             = "1.0"

      hash                = "a2e0adc209c132ed579c15aed1b1d3c5ea34c4953c7ac42d6a8a4fb74d92e3c7"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "SOFTWARE VERTEX QA LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "11:b1:d2:bb:dd:83:2c:2e:56:0e:ea:a7:9a:0d:75:c0"
      cert_thumbprint     = "F0344631F727ABCF965E77FD8585DDF684D69E51"
      cert_valid_from     = "2025-04-28"
      cert_valid_to       = "2026-04-28"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "11:b1:d2:bb:dd:83:2c:2e:56:0e:ea:a7:9a:0d:75:c0"
      )
}

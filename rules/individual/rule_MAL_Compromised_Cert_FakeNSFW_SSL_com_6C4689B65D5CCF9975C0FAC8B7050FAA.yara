import "pe"

rule MAL_Compromised_Cert_FakeNSFW_SSL_com_6C4689B65D5CCF9975C0FAC8B7050FAA {
   meta:
      description         = "Detects FakeNSFW with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-13"
      version             = "1.0"

      hash                = "31e5b56e90d12bbfe6d05028043c16bc999817d077ae2a53ebb64bff576d1586"
      malware             = "FakeNSFW"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "ZAKS SOLUTIONS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6c:46:89:b6:5d:5c:cf:99:75:c0:fa:c8:b7:05:0f:aa"
      cert_thumbprint     = "7BDFDBE77C69FF61DCFB85A3CEDAE9431BE6699D"
      cert_valid_from     = "2025-08-13"
      cert_valid_to       = "2026-08-13"

      country             = "GB"
      state               = "???"
      locality            = "Bolton"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6c:46:89:b6:5d:5c:cf:99:75:c0:fa:c8:b7:05:0f:aa"
      )
}

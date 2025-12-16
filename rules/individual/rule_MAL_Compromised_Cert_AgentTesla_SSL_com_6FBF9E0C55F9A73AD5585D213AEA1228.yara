import "pe"

rule MAL_Compromised_Cert_AgentTesla_SSL_com_6FBF9E0C55F9A73AD5585D213AEA1228 {
   meta:
      description         = "Detects AgentTesla with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-11"
      version             = "1.0"

      hash                = "55cb1bfa69a0b593f98303a2b763f89eb204298da1ebdf2f426a15549cbd29d2"
      malware             = "AgentTesla"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DENEB Software s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6f:bf:9e:0c:55:f9:a7:3a:d5:58:5d:21:3a:ea:12:28"
      cert_thumbprint     = "15307CEEFF8BE2A658CFDCF745CE5B851FBB6819"
      cert_valid_from     = "2025-03-11"
      cert_valid_to       = "2026-03-11"

      country             = "CZ"
      state               = "Praha, Hlavní město"
      locality            = "Stodůlky"
      email               = "???"
      rdn_serial_number   = "09082301"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6f:bf:9e:0c:55:f9:a7:3a:d5:58:5d:21:3a:ea:12:28"
      )
}

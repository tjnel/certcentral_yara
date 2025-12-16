import "pe"

rule MAL_Compromised_Cert_AgentTesla_SSL_com_7ECB39B8913C25A3E6546E3689AA9DE6 {
   meta:
      description         = "Detects AgentTesla with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-18"
      version             = "1.0"

      hash                = "b647e553e3de2f48ce32db71952f4c89b1ce74bd332ecf123723d069767a8139"
      malware             = "AgentTesla"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TA Digital Solutions Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7e:cb:39:b8:91:3c:25:a3:e6:54:6e:36:89:aa:9d:e6"
      cert_thumbprint     = "799E3E90A2CAE4989D93FE36DFA3D4A67EBDA2A0"
      cert_valid_from     = "2025-06-18"
      cert_valid_to       = "2026-06-18"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Kauniainen"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7e:cb:39:b8:91:3c:25:a3:e6:54:6e:36:89:aa:9d:e6"
      )
}

import "pe"

rule MAL_Compromised_Cert_FakeChromeUpdate_SSL_com_6C96E1E122F63716AE8C4AD0DC65A6C4 {
   meta:
      description         = "Detects FakeChromeUpdate with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-11"
      version             = "1.0"

      hash                = "8ba73ef5cf6267c37326e6565bf457b0fc44e5fa018caad102ae42a420db14e1"
      malware             = "FakeChromeUpdate"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JS IT-konsultointi Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6c:96:e1:e1:22:f6:37:16:ae:8c:4a:d0:dc:65:a6:c4"
      cert_thumbprint     = "52D22621327B99E85755CBC0B4F8B06132057C5F"
      cert_valid_from     = "2025-06-11"
      cert_valid_to       = "2026-06-11"

      country             = "FI"
      state               = "Pirkanmaa"
      locality            = "TAMPERE"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6c:96:e1:e1:22:f6:37:16:ae:8c:4a:d0:dc:65:a6:c4"
      )
}

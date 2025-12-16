import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_5A5918074DE23BEC5F344BBACC7A3A90 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-26"
      version             = "1.0"

      hash                = "5e57136b6fa43c0f9c024d18d22be151e0f05be08796ae28d6f9623a07a2aa64"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THE COPY CAT LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5a:59:18:07:4d:e2:3b:ec:5f:34:4b:ba:cc:7a:3a:90"
      cert_thumbprint     = "89A309FE672759A6DAA730C698E26B62BE093927"
      cert_valid_from     = "2025-09-26"
      cert_valid_to       = "2026-09-26"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5a:59:18:07:4d:e2:3b:ec:5f:34:4b:ba:cc:7a:3a:90"
      )
}

import "pe"

rule MAL_Compromised_Cert_LummaStealer_SSL_com_48909C7C626AB37268C151E2FA82D923 {
   meta:
      description         = "Detects LummaStealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-04"
      version             = "1.0"

      hash                = "324e1c80d9accb9ef7f96006122b41d3af33cbd74c47a5240537a17fe20110f1"
      malware             = "LummaStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "SOLVED BY AI LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "48:90:9c:7c:62:6a:b3:72:68:c1:51:e2:fa:82:d9:23"
      cert_thumbprint     = "B6D2B4459D1F8E3F3351761CF1B244FD50430DAA"
      cert_valid_from     = "2025-03-04"
      cert_valid_to       = "2026-03-04"

      country             = "GB"
      state               = "???"
      locality            = "Edinburgh"
      email               = "???"
      rdn_serial_number   = "SC653985"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "48:90:9c:7c:62:6a:b3:72:68:c1:51:e2:fa:82:d9:23"
      )
}

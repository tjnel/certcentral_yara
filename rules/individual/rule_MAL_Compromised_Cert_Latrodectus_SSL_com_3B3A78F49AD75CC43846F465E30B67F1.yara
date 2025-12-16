import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_3B3A78F49AD75CC43846F465E30B67F1 {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-14"
      version             = "1.0"

      hash                = "dd62428e997903e9d2b8e8319fe3a7a57d4e87599d46894b1f9f6f31f7872701"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tietotekniikkapalvelu Risto Kaukua Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3b:3a:78:f4:9a:d7:5c:c4:38:46:f4:65:e3:0b:67:f1"
      cert_thumbprint     = "646B3C129E9A85D332FC8F7D3D3E181C6BD74181"
      cert_valid_from     = "2025-04-14"
      cert_valid_to       = "2026-04-14"

      country             = "FI"
      state               = "Lappi"
      locality            = "Saarenkylä"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3b:3a:78:f4:9a:d7:5c:c4:38:46:f4:65:e3:0b:67:f1"
      )
}

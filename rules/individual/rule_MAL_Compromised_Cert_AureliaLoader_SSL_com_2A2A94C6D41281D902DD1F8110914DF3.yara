import "pe"

rule MAL_Compromised_Cert_AureliaLoader_SSL_com_2A2A94C6D41281D902DD1F8110914DF3 {
   meta:
      description         = "Detects AureliaLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-21"
      version             = "1.0"

      hash                = "c55526f2351a24aa298b99b26a6873bafaa274fa8d9ed57d78fc154d3d90cc8d"
      malware             = "AureliaLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SG SOFT SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2a:2a:94:c6:d4:12:81:d9:02:dd:1f:81:10:91:4d:f3"
      cert_thumbprint     = "8235085B7D6380CFF005D5DC6DF0C942C9DA97AE"
      cert_valid_from     = "2025-08-21"
      cert_valid_to       = "2026-08-21"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2a:2a:94:c6:d4:12:81:d9:02:dd:1f:81:10:91:4d:f3"
      )
}

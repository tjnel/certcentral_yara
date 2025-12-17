import "pe"

rule MAL_Compromised_Cert_AureliaLoader_SSL_com_5F6475DF5A682F22DA05AF64DD2B6CEE {
   meta:
      description         = "Detects AureliaLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-31"
      version             = "1.0"

      hash                = "d69e7d79557fedb5baccad54c1282579f289780807a1debbc7adedeaa2019179"
      malware             = "AureliaLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "QORs"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5f:64:75:df:5a:68:2f:22:da:05:af:64:dd:2b:6c:ee"
      cert_thumbprint     = "11EC2DE14E10EBE7574FB8DFD57E6926C6D62634"
      cert_valid_from     = "2025-07-31"
      cert_valid_to       = "2026-07-31"

      country             = "BE"
      state               = "Flanders"
      locality            = "Dilbeek"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5f:64:75:df:5a:68:2f:22:da:05:af:64:dd:2b:6c:ee"
      )
}

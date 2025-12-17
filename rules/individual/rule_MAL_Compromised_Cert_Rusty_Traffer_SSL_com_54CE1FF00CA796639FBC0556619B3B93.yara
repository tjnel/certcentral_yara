import "pe"

rule MAL_Compromised_Cert_Rusty_Traffer_SSL_com_54CE1FF00CA796639FBC0556619B3B93 {
   meta:
      description         = "Detects Rusty Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-24"
      version             = "1.0"

      hash                = "d3650780da767130efa079252782fe5a70d18b702a6c2b7bd643479c750e6ea8"
      malware             = "Rusty Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "QENTRA SOFTWARE LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "54:ce:1f:f0:0c:a7:96:63:9f:bc:05:56:61:9b:3b:93"
      cert_thumbprint     = "FBA9E20D4B3A4777AA086AA2C9483554398CED88"
      cert_valid_from     = "2025-07-24"
      cert_valid_to       = "2026-07-24"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "54:ce:1f:f0:0c:a7:96:63:9f:bc:05:56:61:9b:3b:93"
      )
}

import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_032D7744466225316CC99B0E088E4A3E {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-04"
      version             = "1.0"

      hash                = "eca7889b628fb20ae86772da86f6672d393bcee3ff0e7a49a2f1e4f161cf8bc4"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JJK Software Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "03:2d:77:44:46:62:25:31:6c:c9:9b:0e:08:8e:4a:3e"
      cert_thumbprint     = "C60D447EFEFC117B6EC1499374448B79F5B57E28"
      cert_valid_from     = "2024-11-04"
      cert_valid_to       = "2025-11-04"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Espoo"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "03:2d:77:44:46:62:25:31:6c:c9:9b:0e:08:8e:4a:3e"
      )
}

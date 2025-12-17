import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_219611E14FA18CE517821CEFBA2AD1C9 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-22"
      version             = "1.0"

      hash                = "781d7b5cacf74dd23d6a64c8ad4768abcb0c295d3ce854b58ca2091469678e26"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IT Consilium Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "21:96:11:e1:4f:a1:8c:e5:17:82:1c:ef:ba:2a:d1:c9"
      cert_thumbprint     = "D6B48E6561731361C4F35AFEE134D39B7E3D4B6B"
      cert_valid_from     = "2024-08-22"
      cert_valid_to       = "2025-08-22"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "3216225-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "21:96:11:e1:4f:a1:8c:e5:17:82:1c:ef:ba:2a:d1:c9"
      )
}

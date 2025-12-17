import "pe"

rule MAL_Compromised_Cert_Pikabot_SSL_com_79695808028C2494541535419610A4E0 {
   meta:
      description         = "Detects Pikabot with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-19"
      version             = "1.0"

      hash                = "1626880b917b7f5756109dcb6533a5dbae859ccd841554e5bdb6c602cc3a9226"
      malware             = "Pikabot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Talk Invest ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "79:69:58:08:02:8c:24:94:54:15:35:41:96:10:a4:e0"
      cert_thumbprint     = "7B75394FF02197A21E6F683A717CB5A94C7C3DAE"
      cert_valid_from     = "2024-01-19"
      cert_valid_to       = "2025-01-18"

      country             = "DK"
      state               = "Region of Southern Denmark"
      locality            = "Tommerup"
      email               = "???"
      rdn_serial_number   = "40777555"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "79:69:58:08:02:8c:24:94:54:15:35:41:96:10:a4:e0"
      )
}

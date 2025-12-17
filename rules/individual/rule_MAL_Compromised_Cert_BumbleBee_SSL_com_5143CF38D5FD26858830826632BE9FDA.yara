import "pe"

rule MAL_Compromised_Cert_BumbleBee_SSL_com_5143CF38D5FD26858830826632BE9FDA {
   meta:
      description         = "Detects BumbleBee with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-10-31"
      version             = "1.0"

      hash                = "cab63e05a4a6f0b825acb077ba6a1bbb3657488c584882124a31c45dfb39515d"
      malware             = "BumbleBee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DIGI CORP MEDIA LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "51:43:cf:38:d5:fd:26:85:88:30:82:66:32:be:9f:da"
      cert_thumbprint     = "C482CE18FB7460B55A25C10B2583C2FA16019A5B"
      cert_valid_from     = "2022-10-31"
      cert_valid_to       = "2023-10-31"

      country             = "US"
      state               = "Nevada"
      locality            = "Henderson"
      email               = "???"
      rdn_serial_number   = "NV20222585426"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "51:43:cf:38:d5:fd:26:85:88:30:82:66:32:be:9f:da"
      )
}

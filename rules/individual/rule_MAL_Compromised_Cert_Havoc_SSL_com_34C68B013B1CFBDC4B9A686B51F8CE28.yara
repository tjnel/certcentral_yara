import "pe"

rule MAL_Compromised_Cert_Havoc_SSL_com_34C68B013B1CFBDC4B9A686B51F8CE28 {
   meta:
      description         = "Detects Havoc with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-12"
      version             = "1.0"

      hash                = "3e3c562b6558026031a976a88347638eddcb97b9380da8a4453d96eb1ceda807"
      malware             = "Havoc"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TST ENGINEERING JOINT STOCK COMPANY"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "34:c6:8b:01:3b:1c:fb:dc:4b:9a:68:6b:51:f8:ce:28"
      cert_thumbprint     = "250D57689E956AE3C3E5A9A95A869E251123BFCB"
      cert_valid_from     = "2024-09-12"
      cert_valid_to       = "2025-09-12"

      country             = "VN"
      state               = "???"
      locality            = "Ha Noi"
      email               = "???"
      rdn_serial_number   = "0101802137"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "34:c6:8b:01:3b:1c:fb:dc:4b:9a:68:6b:51:f8:ce:28"
      )
}

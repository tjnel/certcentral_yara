import "pe"

rule MAL_Compromised_Cert_Havoc_SSL_com_1966BC76BDA1A708334792DA9A336F69 {
   meta:
      description         = "Detects Havoc with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-19"
      version             = "1.0"

      hash                = "ee4820ed792f7e6a07b33f041b855b330a8c968a214f5e475f539b4cfdcd65c1"
      malware             = "Havoc"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SYNTHETIC LABS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "19:66:bc:76:bd:a1:a7:08:33:47:92:da:9a:33:6f:69"
      cert_thumbprint     = "29FEC27C36EFC6809C7269F76CF86EE18CC6ED87"
      cert_valid_from     = "2023-05-19"
      cert_valid_to       = "2024-05-16"

      country             = "GB"
      state               = "???"
      locality            = "St. Albans"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "19:66:bc:76:bd:a1:a7:08:33:47:92:da:9a:33:6f:69"
      )
}

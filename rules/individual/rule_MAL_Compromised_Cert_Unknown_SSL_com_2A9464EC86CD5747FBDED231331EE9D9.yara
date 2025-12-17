import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_2A9464EC86CD5747FBDED231331EE9D9 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-17"
      version             = "1.0"

      hash                = "750b9fe259311e22acbcb1d2e69e20bdf378d468f6b8fd4a0e938c8efa304768"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mushroom Software"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "2a:94:64:ec:86:cd:57:47:fb:de:d2:31:33:1e:e9:d9"
      cert_thumbprint     = "2add8dda84d748eecbd60c9ae0649c475c801b62632005b48d68c9f414f1e4e7"
      cert_valid_from     = "2025-01-17"
      cert_valid_to       = "2026-01-17"

      country             = "FR"
      state               = "Île-de-France"
      locality            = "Saint-Fargeau-Ponthierry"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "2a:94:64:ec:86:cd:57:47:fb:de:d2:31:33:1e:e9:d9"
      )
}

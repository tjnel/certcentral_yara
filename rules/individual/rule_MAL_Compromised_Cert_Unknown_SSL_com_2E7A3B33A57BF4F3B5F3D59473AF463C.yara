import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_2E7A3B33A57BF4F3B5F3D59473AF463C {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-14"
      version             = "1.0"

      hash                = "6ca519083401cfa60ecf35d94ccd4012a12d7d87a656e4a1a678e0a7729c49a2"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Uconfig Digital Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2e:7a:3b:33:a5:7b:f4:f3:b5:f3:d5:94:73:af:46:3c"
      cert_thumbprint     = "54CF2850A07B4E1F4B3081DCB465FB384B140305"
      cert_valid_from     = "2025-10-14"
      cert_valid_to       = "2026-06-06"

      country             = "PL"
      state               = "Lower Silesian Voivodeship"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2e:7a:3b:33:a5:7b:f4:f3:b5:f3:d5:94:73:af:46:3c"
      )
}

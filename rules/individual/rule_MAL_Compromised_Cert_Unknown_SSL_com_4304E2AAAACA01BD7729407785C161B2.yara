import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_4304E2AAAACA01BD7729407785C161B2 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-28"
      version             = "1.0"

      hash                = "24e265deef02a8ed892dd85a3c704d0a4fdea9d10e31c3aa4589f39fca64dd1a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ferrets Incorporated Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "43:04:e2:aa:aa:ca:01:bd:77:29:40:77:85:c1:61:b2"
      cert_thumbprint     = "2AC0CC82E2E696BDE53B6F13A8DB4CB034D9BBE5"
      cert_valid_from     = "2024-08-28"
      cert_valid_to       = "2025-08-27"

      country             = "GB"
      state               = "???"
      locality            = "Woodhall Spa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "43:04:e2:aa:aa:ca:01:bd:77:29:40:77:85:c1:61:b2"
      )
}

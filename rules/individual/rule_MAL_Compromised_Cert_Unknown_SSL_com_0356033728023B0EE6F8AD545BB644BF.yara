import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_0356033728023B0EE6F8AD545BB644BF {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-04"
      version             = "1.0"

      hash                = "0a263703a49b6220a5b05b83ce9a89528e16cd09efb3c6e7671344c8ddb5c224"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BITO LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "03:56:03:37:28:02:3b:0e:e6:f8:ad:54:5b:b6:44:bf"
      cert_thumbprint     = "121CD886BA98077648FB3C27EFAA007E268DBD57"
      cert_valid_from     = "2024-10-04"
      cert_valid_to       = "2025-10-04"

      country             = "KE"
      state               = "Nakuru County"
      locality            = "Nakuru"
      email               = "???"
      rdn_serial_number   = "CPR/2010/17797"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "03:56:03:37:28:02:3b:0e:e6:f8:ad:54:5b:b6:44:bf"
      )
}

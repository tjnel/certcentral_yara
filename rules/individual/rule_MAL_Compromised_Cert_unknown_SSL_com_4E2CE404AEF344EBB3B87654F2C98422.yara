import "pe"

rule MAL_Compromised_Cert_unknown_SSL_com_4E2CE404AEF344EBB3B87654F2C98422 {
   meta:
      description         = "Detects unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-15"
      version             = "1.0"

      hash                = "7e33a3b6de352650c44163c2ff989cad764017c508e13b240f783c08c736f2c5"
      malware             = "unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Max Biotech Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4e:2c:e4:04:ae:f3:44:eb:b3:b8:76:54:f2:c9:84:22"
      cert_thumbprint     = "5A6D836E89DE99ADEF95667B3A921B7DA044B3F8"
      cert_valid_from     = "2024-03-15"
      cert_valid_to       = "2025-03-15"

      country             = "GB"
      state               = "???"
      locality            = "Caterham"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4e:2c:e4:04:ae:f3:44:eb:b3:b8:76:54:f2:c9:84:22"
      )
}

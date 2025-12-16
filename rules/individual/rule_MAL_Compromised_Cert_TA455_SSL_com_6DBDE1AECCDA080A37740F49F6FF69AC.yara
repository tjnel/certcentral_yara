import "pe"

rule MAL_Compromised_Cert_TA455_SSL_com_6DBDE1AECCDA080A37740F49F6FF69AC {
   meta:
      description         = "Detects TA455 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-24"
      version             = "1.0"

      hash                = "3b58fd0c0ef8a42226be4d26a64235da059986ec7f5990d5c50d47b7a6cfadcd"
      malware             = "TA455"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RGC Digital AB"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6d:bd:e1:ae:cc:da:08:0a:37:74:0f:49:f6:ff:69:ac"
      cert_thumbprint     = "9CC577B29B87E50C2C3917F8DF1628FE8579F067"
      cert_valid_from     = "2025-06-24"
      cert_valid_to       = "2026-06-24"

      country             = "SE"
      state               = "Stockholm County"
      locality            = "Stockholm"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6d:bd:e1:ae:cc:da:08:0a:37:74:0f:49:f6:ff:69:ac"
      )
}

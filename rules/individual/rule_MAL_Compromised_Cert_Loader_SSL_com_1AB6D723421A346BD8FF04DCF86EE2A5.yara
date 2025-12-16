import "pe"

rule MAL_Compromised_Cert_Loader_SSL_com_1AB6D723421A346BD8FF04DCF86EE2A5 {
   meta:
      description         = "Detects Loader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-10"
      version             = "1.0"

      hash                = "54f4be3601111cb57393d22318fc401bbb4a2098bab28d61f96119c7f9f53df2"
      malware             = "Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Cult of the North AB"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1a:b6:d7:23:42:1a:34:6b:d8:ff:04:dc:f8:6e:e2:a5"
      cert_thumbprint     = "ED087A063012813B615029727B164A9611FCE135"
      cert_valid_from     = "2025-02-10"
      cert_valid_to       = "2026-03-18"

      country             = "SE"
      state               = "Stockholm County"
      locality            = "Stockholm"
      email               = "???"
      rdn_serial_number   = "559360-1908"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1a:b6:d7:23:42:1a:34:6b:d8:ff:04:dc:f8:6e:e2:a5"
      )
}

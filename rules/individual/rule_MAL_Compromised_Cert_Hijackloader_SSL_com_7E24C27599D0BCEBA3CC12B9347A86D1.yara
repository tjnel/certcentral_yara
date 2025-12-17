import "pe"

rule MAL_Compromised_Cert_Hijackloader_SSL_com_7E24C27599D0BCEBA3CC12B9347A86D1 {
   meta:
      description         = "Detects Hijackloader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-28"
      version             = "1.0"

      hash                = "5fe9e516f35fff47564762f9bcb9804f73df817ebe12f8fc4d85e586f4542b6b"
      malware             = "Hijackloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Raastuff Holding ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7e:24:c2:75:99:d0:bc:eb:a3:cc:12:b9:34:7a:86:d1"
      cert_thumbprint     = "48BD9CC83CBB844CDBC911C14A3C6D2C2BF9DA6A"
      cert_valid_from     = "2025-06-28"
      cert_valid_to       = "2026-06-28"

      country             = "DK"
      state               = "Region of Southern Denmark"
      locality            = "Odense"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7e:24:c2:75:99:d0:bc:eb:a3:cc:12:b9:34:7a:86:d1"
      )
}

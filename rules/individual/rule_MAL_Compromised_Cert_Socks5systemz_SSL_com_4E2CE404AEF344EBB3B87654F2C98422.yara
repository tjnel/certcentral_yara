import "pe"

rule MAL_Compromised_Cert_Socks5systemz_SSL_com_4E2CE404AEF344EBB3B87654F2C98422 {
   meta:
      description         = "Detects Socks5systemz with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-14"
      version             = "1.0"

      hash                = "22aee22dda57ee1891a90019d4e84a173c73dcdc12f74d0064c6439fb4f4c81d"
      malware             = "Socks5systemz"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Max Biotech Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4e:2c:e4:04:ae:f3:44:eb:b3:b8:76:54:f2:c9:84:22"
      cert_thumbprint     = "5A6D836E89DE99ADEF95667B3A921B7DA044B3F8"
      cert_valid_from     = "2024-03-14"
      cert_valid_to       = "2025-03-14"

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

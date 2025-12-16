import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_69C55475FFD7B1A2474296E14C5CF8D9 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-11"
      version             = "1.0"

      hash                = "79b6e63218982c1e85a5e1798c5484e7e034cfecbe9f2da604f668fda8428af4"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INDCARE AFRICA LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "69:c5:54:75:ff:d7:b1:a2:47:42:96:e1:4c:5c:f8:d9"
      cert_thumbprint     = "643F5BE0BC3ED89ADE028AAF7AA5D50B84C50E8F"
      cert_valid_from     = "2024-11-11"
      cert_valid_to       = "2025-11-11"

      country             = "KE"
      state               = "???"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "CPR/2009/10319"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "69:c5:54:75:ff:d7:b1:a2:47:42:96:e1:4c:5c:f8:d9"
      )
}

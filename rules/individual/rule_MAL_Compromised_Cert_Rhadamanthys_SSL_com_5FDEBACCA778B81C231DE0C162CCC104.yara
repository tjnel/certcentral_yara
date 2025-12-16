import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_5FDEBACCA778B81C231DE0C162CCC104 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-15"
      version             = "1.0"

      hash                = "2e338036cf49cf618430ab452a87b5a748a5443ad093ff6b49a71d0cf5af373b"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "GALAXY HOMES LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5f:de:ba:cc:a7:78:b8:1c:23:1d:e0:c1:62:cc:c1:04"
      cert_thumbprint     = "B407912B0421E763505C91C0F0AAC02D850F930C"
      cert_valid_from     = "2025-09-15"
      cert_valid_to       = "2026-09-15"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5f:de:ba:cc:a7:78:b8:1c:23:1d:e0:c1:62:cc:c1:04"
      )
}

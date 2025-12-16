import "pe"

rule MAL_Compromised_Cert_GoblinLoader_SSL_com_19A65FD06F2F1433306F3968848F40CE {
   meta:
      description         = "Detects GoblinLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-13"
      version             = "1.0"

      hash                = "28da14b5f7e5f0bc5a075525d13eb4260ee3f5f592f16846dffa8d8e9724ca80"
      malware             = "GoblinLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Cascade Tech-Trek Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "19:a6:5f:d0:6f:2f:14:33:30:6f:39:68:84:8f:40:ce"
      cert_thumbprint     = "04DF18CF4F6AC1E42B6F6D0487D2F1461314F99D"
      cert_valid_from     = "2024-12-13"
      cert_valid_to       = "2025-12-13"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Burnaby"
      email               = "???"
      rdn_serial_number   = "771956-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "19:a6:5f:d0:6f:2f:14:33:30:6f:39:68:84:8f:40:ce"
      )
}

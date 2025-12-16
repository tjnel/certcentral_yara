import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_7A1D9DFB337DB9260B223D2D1D71A559 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-26"
      version             = "1.0"

      hash                = "2ce42584e83228377d4513d8503bcd10aa2cd4a23c4a87f1b57ef3a081361552"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sukhpreet Singh"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "7a:1d:9d:fb:33:7d:b9:26:0b:22:3d:2d:1d:71:a5:59"
      cert_thumbprint     = "AF179EDB2224E472BD9DAE781027CB3E0EC40872"
      cert_valid_from     = "2024-07-26"
      cert_valid_to       = "2025-07-26"

      country             = "IN"
      state               = "Punjab"
      locality            = "Amritsar"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "7a:1d:9d:fb:33:7d:b9:26:0b:22:3d:2d:1d:71:a5:59"
      )
}

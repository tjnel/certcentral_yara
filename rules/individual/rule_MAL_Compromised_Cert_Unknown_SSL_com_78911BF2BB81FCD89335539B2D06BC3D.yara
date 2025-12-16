import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_78911BF2BB81FCD89335539B2D06BC3D {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-06"
      version             = "1.0"

      hash                = "6eeb6689fd6cdc2cfac77a0ab6741e5ee2d56129af63d609f1365032070c9a22"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Commander Software Solutions Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "78:91:1b:f2:bb:81:fc:d8:93:35:53:9b:2d:06:bc:3d"
      cert_thumbprint     = "B203838512C07B674B4E7B76D6D8214910C0FCF0"
      cert_valid_from     = "2024-08-06"
      cert_valid_to       = "2025-08-06"

      country             = "FI"
      state               = "Varsinais-Suomi"
      locality            = "Turku"
      email               = "???"
      rdn_serial_number   = "3019213-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "78:91:1b:f2:bb:81:fc:d8:93:35:53:9b:2d:06:bc:3d"
      )
}

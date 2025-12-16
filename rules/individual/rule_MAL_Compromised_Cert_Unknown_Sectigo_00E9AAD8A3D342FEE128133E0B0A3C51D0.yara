import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00E9AAD8A3D342FEE128133E0B0A3C51D0 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-13"
      version             = "1.0"

      hash                = "b285a84fab8597de852adeadf3dcbe3f32bf40965bce789b057e987615cfaf83"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "55.604.504 Rafael Ferreira de Carvalho"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:e9:aa:d8:a3:d3:42:fe:e1:28:13:3e:0b:0a:3c:51:d0"
      cert_thumbprint     = "704ACB8A8C5F1A52843D1A509E2D5BFE7C8325D8"
      cert_valid_from     = "2025-01-13"
      cert_valid_to       = "2025-10-30"

      country             = "BR"
      state               = "Distrito Federal"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "55.604.504/0001-02"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:e9:aa:d8:a3:d3:42:fe:e1:28:13:3e:0b:0a:3c:51:d0"
      )
}

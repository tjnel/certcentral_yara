import "pe"

rule MAL_Compromised_Cert_Eclipse_Traffer_Team_SSL_com_43F983BDCA260C253FB332394352C5F6 {
   meta:
      description         = "Detects Eclipse Traffer Team with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-30"
      version             = "1.0"

      hash                = "deef7b287e2b5d2cc1e22366eedee09031fca511ab0741a341f40dc82ba74453"
      malware             = "Eclipse Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DEAL STANDART SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "43:f9:83:bd:ca:26:0c:25:3f:b3:32:39:43:52:c5:f6"
      cert_thumbprint     = "F62D1202AB28201D22399F83BD0DAFC8A8D2F37B"
      cert_valid_from     = "2025-07-30"
      cert_valid_to       = "2026-07-30"

      country             = "PL"
      state               = "Lower Silesian Voivodeship"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "43:f9:83:bd:ca:26:0c:25:3f:b3:32:39:43:52:c5:f6"
      )
}

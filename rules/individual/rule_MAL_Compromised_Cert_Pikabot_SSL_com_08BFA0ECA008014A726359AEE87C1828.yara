import "pe"

rule MAL_Compromised_Cert_Pikabot_SSL_com_08BFA0ECA008014A726359AEE87C1828 {
   meta:
      description         = "Detects Pikabot with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-15"
      version             = "1.0"

      hash                = "6c91b714aefef2438be04161d812403279c2da887902f9e979e83ace50dbb37a"
      malware             = "Pikabot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ARCHIKADIA SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "08:bf:a0:ec:a0:08:01:4a:72:63:59:ae:e8:7c:18:28"
      cert_thumbprint     = "566E7BCC466E79F9A21D4FF7DFF0A407D76B41F9"
      cert_valid_from     = "2024-01-15"
      cert_valid_to       = "2025-01-14"

      country             = "PL"
      state               = "Malopolskie"
      locality            = "Krakow"
      email               = "???"
      rdn_serial_number   = "0000806540"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "08:bf:a0:ec:a0:08:01:4a:72:63:59:ae:e8:7c:18:28"
      )
}

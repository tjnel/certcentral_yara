import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_SSL_com_65897B2D2ADF2946F895D98F627E5D86 {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-03"
      version             = "1.0"

      hash                = "d4abd215ec31afa8738aed827e2fdb2e4de18aa5dad70d95874ac87e5bc93988"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SUPERNOVA SOFTWARE CONSULTANCY LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "65:89:7b:2d:2a:df:29:46:f8:95:d9:8f:62:7e:5d:86"
      cert_thumbprint     = "278E182D4055B9D064A0222C7EA79373450A903A"
      cert_valid_from     = "2025-03-03"
      cert_valid_to       = "2026-03-03"

      country             = "GB"
      state               = "???"
      locality            = "Ipswich"
      email               = "???"
      rdn_serial_number   = "11788397"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "65:89:7b:2d:2a:df:29:46:f8:95:d9:8f:62:7e:5d:86"
      )
}

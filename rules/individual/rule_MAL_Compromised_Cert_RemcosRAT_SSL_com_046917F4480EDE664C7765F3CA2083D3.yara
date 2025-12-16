import "pe"

rule MAL_Compromised_Cert_RemcosRAT_SSL_com_046917F4480EDE664C7765F3CA2083D3 {
   meta:
      description         = "Detects RemcosRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-13"
      version             = "1.0"

      hash                = "5907944373d327917b8bbac448b56548206c30da715d2a400318dda0a46906a8"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hi Resolution Software Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "04:69:17:f4:48:0e:de:66:4c:77:65:f3:ca:20:83:d3"
      cert_thumbprint     = "0C7F9FB37FC85C15E6702F7A9A1FE85ACCAB1BBB"
      cert_valid_from     = "2025-08-13"
      cert_valid_to       = "2026-08-13"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "04:69:17:f4:48:0e:de:66:4c:77:65:f3:ca:20:83:d3"
      )
}

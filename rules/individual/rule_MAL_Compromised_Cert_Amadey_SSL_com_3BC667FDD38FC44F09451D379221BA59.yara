import "pe"

rule MAL_Compromised_Cert_Amadey_SSL_com_3BC667FDD38FC44F09451D379221BA59 {
   meta:
      description         = "Detects Amadey with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-07"
      version             = "1.0"

      hash                = "d8acd41403f44fb7c4f32f0e641b361d1268a882c73d8c785e2225b7b022b312"
      malware             = "Amadey"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Cnet Design Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3b:c6:67:fd:d3:8f:c4:4f:09:45:1d:37:92:21:ba:59"
      cert_thumbprint     = "73ADE409A35F3E84A3400E7E361E49F834D16FF1"
      cert_valid_from     = "2024-05-07"
      cert_valid_to       = "2025-05-07"

      country             = "GB"
      state               = "???"
      locality            = "Uxbridge"
      email               = "???"
      rdn_serial_number   = "08743106"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3b:c6:67:fd:d3:8f:c4:4f:09:45:1d:37:92:21:ba:59"
      )
}

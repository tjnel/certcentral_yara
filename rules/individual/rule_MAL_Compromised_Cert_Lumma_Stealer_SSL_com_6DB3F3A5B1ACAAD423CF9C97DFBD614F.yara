import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_6DB3F3A5B1ACAAD423CF9C97DFBD614F {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-05"
      version             = "1.0"

      hash                = "9100672d5ec3631ff800ae7017f74b085b651a6027dcbe77bbfab67ef0e63c48"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Macpaw Labs LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6d:b3:f3:a5:b1:ac:aa:d4:23:cf:9c:97:df:bd:61:4f"
      cert_thumbprint     = "45A0D462D05753C864CD011C7C022262A23CF169"
      cert_valid_from     = "2024-09-05"
      cert_valid_to       = "2025-09-05"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "09221780"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6d:b3:f3:a5:b1:ac:aa:d4:23:cf:9c:97:df:bd:61:4f"
      )
}

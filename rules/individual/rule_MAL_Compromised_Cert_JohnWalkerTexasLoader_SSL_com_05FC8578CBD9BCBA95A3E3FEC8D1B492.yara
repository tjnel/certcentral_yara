import "pe"

rule MAL_Compromised_Cert_JohnWalkerTexasLoader_SSL_com_05FC8578CBD9BCBA95A3E3FEC8D1B492 {
   meta:
      description         = "Detects JohnWalkerTexasLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-16"
      version             = "1.0"

      hash                = "44d770ca66fbf194a8f1448dbebc5b5679fd2ac4912ceafbb0fac21eac28eccd"
      malware             = "JohnWalkerTexasLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "H PLUS CARE LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "05:fc:85:78:cb:d9:bc:ba:95:a3:e3:fe:c8:d1:b4:92"
      cert_thumbprint     = "54DD7092F9307D4F8E2F4D965C7E0085C430BAB2"
      cert_valid_from     = "2024-10-16"
      cert_valid_to       = "2025-10-16"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "05736767"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "05:fc:85:78:cb:d9:bc:ba:95:a3:e3:fe:c8:d1:b4:92"
      )
}

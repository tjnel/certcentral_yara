import "pe"

rule MAL_Compromised_Cert_GoblinLoader_SSL_com_01F9C8D6A864B87722B7EDDB621BD1EB {
   meta:
      description         = "Detects GoblinLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-17"
      version             = "1.0"

      hash                = "a5077a730f5f178416d797f96942d2fc3b632ae449495a4be8525a4289a97274"
      malware             = "GoblinLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "VE Development sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "01:f9:c8:d6:a8:64:b8:77:22:b7:ed:db:62:1b:d1:eb"
      cert_thumbprint     = "63b3e89bf11421670f8de04312fd248ad122149bdac5c4501d84e7f71cc389f7"
      cert_valid_from     = "2025-02-17"
      cert_valid_to       = "2026-02-17"

      country             = "PL"
      state               = "???"
      locality            = "Łódź"
      email               = "???"
      rdn_serial_number   = "0000946525"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "01:f9:c8:d6:a8:64:b8:77:22:b7:ed:db:62:1b:d1:eb"
      )
}

import "pe"

rule MAL_Compromised_Cert_FakeDocument_SSL_com_700B215E33D4D6E0613324E8DCEFE4FF {
   meta:
      description         = "Detects FakeDocument with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-10"
      version             = "1.0"

      hash                = "04cc94bf0c8c0e815f1fd4203db8ea040c46c006bc2e25a26144e69cc9cbc8a8"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DECISION CONSULTANT SOLUTIONS LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "70:0b:21:5e:33:d4:d6:e0:61:33:24:e8:dc:ef:e4:ff"
      cert_thumbprint     = "E28CE0005497D24BB9FCFDD622AD2A5C6838FE9D"
      cert_valid_from     = "2025-03-10"
      cert_valid_to       = "2026-03-10"

      country             = "GB"
      state               = "???"
      locality            = "Hull"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "70:0b:21:5e:33:d4:d6:e0:61:33:24:e8:dc:ef:e4:ff"
      )
}

import "pe"

rule MAL_Compromised_Cert_Softwarecloud_SSL_com_700B215E33D4D6E0613324E8DCEFE4FF {
   meta:
      description         = "Detects Softwarecloud with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-10"
      version             = "1.0"

      hash                = "c9a72e7dd2dfe74bec0e37d4cf301ad3141c4adcc2097abf25ca3a156d456e0d"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

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

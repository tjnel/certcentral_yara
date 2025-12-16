import "pe"

rule MAL_Compromised_Cert_Softwarecloud_SSL_com_6C897CD96B9ED39CD2D217E14D0F9357 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-09"
      version             = "1.0"

      hash                = "13d62ccd7bf9244576bbc40674185bc7c126b2665e4ffdb9c8956bf993a332e4"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "IT OFFICE PARK SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6c:89:7c:d9:6b:9e:d3:9c:d2:d2:17:e1:4d:0f:93:57"
      cert_thumbprint     = "CB7D00CEB541D02270E98FECA7B836533D8CB617"
      cert_valid_from     = "2025-05-09"
      cert_valid_to       = "2026-05-09"

      country             = "PL"
      state               = "Lublin Voivodeship"
      locality            = "Lublin"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6c:89:7c:d9:6b:9e:d3:9c:d2:d2:17:e1:4d:0f:93:57"
      )
}

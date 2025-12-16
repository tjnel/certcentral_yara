import "pe"

rule MAL_Compromised_Cert_Vidar_SSL_com_0AD7C373F578C648F98330332B4F3C1A {
   meta:
      description         = "Detects Vidar with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-27"
      version             = "1.0"

      hash                = "6d2ecf5fd4645d4b83401d08dae2e4582bdc0b8162c711edc0de51b9884a883a"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Trazel, LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0a:d7:c3:73:f5:78:c6:48:f9:83:30:33:2b:4f:3c:1a"
      cert_thumbprint     = "D326D1717D831D5475A7732D306C7BBC69411FD5"
      cert_valid_from     = "2025-05-27"
      cert_valid_to       = "2026-05-27"

      country             = "US"
      state               = "Texas"
      locality            = "Richmond"
      email               = "???"
      rdn_serial_number   = "804013133"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0a:d7:c3:73:f5:78:c6:48:f9:83:30:33:2b:4f:3c:1a"
      )
}

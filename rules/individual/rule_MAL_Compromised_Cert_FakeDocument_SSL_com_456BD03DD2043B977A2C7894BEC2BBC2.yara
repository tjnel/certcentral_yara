import "pe"

rule MAL_Compromised_Cert_FakeDocument_SSL_com_456BD03DD2043B977A2C7894BEC2BBC2 {
   meta:
      description         = "Detects FakeDocument with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-29"
      version             = "1.0"

      hash                = "8ffdc7d783f87eab110921b33c74867a5eed7566d67d943f8d7deb5659d60c27"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Digital Sun Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "45:6b:d0:3d:d2:04:3b:97:7a:2c:78:94:be:c2:bb:c2"
      cert_thumbprint     = "B0BECCBCF6F99E8DE68D29C6624156EBE850F9DC"
      cert_valid_from     = "2025-08-29"
      cert_valid_to       = "2026-08-29"

      country             = "PL"
      state               = "Greater Poland Voivodeship"
      locality            = "Poznań"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "45:6b:d0:3d:d2:04:3b:97:7a:2c:78:94:be:c2:bb:c2"
      )
}

import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_52690E015A8EC000D705BF0EB937D7EA {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-24"
      version             = "1.0"

      hash                = "e2b5e92dd942c21c84a593d97483f0136abac73f21b6a7e73b53aaad78c35724"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HALO SOFTWARE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "52:69:0e:01:5a:8e:c0:00:d7:05:bf:0e:b9:37:d7:ea"
      cert_thumbprint     = "B7F9882710AA256310BCEFA3DBE94ED1885C478E"
      cert_valid_from     = "2024-12-24"
      cert_valid_to       = "2025-12-24"

      country             = "GB"
      state               = "???"
      locality            = "Bath"
      email               = "???"
      rdn_serial_number   = "10856341"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "52:69:0e:01:5a:8e:c0:00:d7:05:bf:0e:b9:37:d7:ea"
      )
}

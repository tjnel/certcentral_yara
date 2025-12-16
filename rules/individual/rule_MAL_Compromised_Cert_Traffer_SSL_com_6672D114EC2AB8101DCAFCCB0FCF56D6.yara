import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_6672D114EC2AB8101DCAFCCB0FCF56D6 {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-16"
      version             = "1.0"

      hash                = "46e6e4d2e67b95c2e37c2dc43aeb857cf2cf1a350591881454e6cc5b83a88116"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Miralys Communications Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "66:72:d1:14:ec:2a:b8:10:1d:ca:fc:cb:0f:cf:56:d6"
      cert_thumbprint     = "70111568B476021235D68332E06A8BFA4CCA8EBE"
      cert_valid_from     = "2025-09-16"
      cert_valid_to       = "2026-09-12"

      country             = "CA"
      state               = "Quebec"
      locality            = "Québec"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "66:72:d1:14:ec:2a:b8:10:1d:ca:fc:cb:0f:cf:56:d6"
      )
}

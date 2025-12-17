import "pe"

rule MAL_Compromised_Cert_Oyster_SSL_com_14E52D6A45004663FEF6E69DAAA54FEF {
   meta:
      description         = "Detects Oyster with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-17"
      version             = "1.0"

      hash                = "a4e1c33b1280a0b2daab512b5a4cfdd775743a1980c9b63eb4bfb739356378ae"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "NEETLA LIFESTYLE PRIVATE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "14:e5:2d:6a:45:00:46:63:fe:f6:e6:9d:aa:a5:4f:ef"
      cert_thumbprint     = "4FB21616AA8C7042CCAD9095DA5E14376EE75796"
      cert_valid_from     = "2025-10-17"
      cert_valid_to       = "2026-10-17"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "14:e5:2d:6a:45:00:46:63:fe:f6:e6:9d:aa:a5:4f:ef"
      )
}

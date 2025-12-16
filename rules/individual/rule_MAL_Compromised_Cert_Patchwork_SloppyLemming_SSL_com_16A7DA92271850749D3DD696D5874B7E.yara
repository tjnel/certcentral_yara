import "pe"

rule MAL_Compromised_Cert_Patchwork_SloppyLemming_SSL_com_16A7DA92271850749D3DD696D5874B7E {
   meta:
      description         = "Detects Patchwork,SloppyLemming with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-31"
      version             = "1.0"

      hash                = "331e7af55dc9e985a7918926b308ca3c24b1c47257c187de6481354c96f95b1e"
      malware             = "Patchwork,SloppyLemming"
      malware_type        = "Backdoor"
      malware_notes       = "The malware is delivered via phishing, disguised as a document. The malware may be involved in espionage activities targeting South East Asian organizations."

      signer              = "Fidus Software Consulting Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "16:a7:da:92:27:18:50:74:9d:3d:d6:96:d5:87:4b:7e"
      cert_thumbprint     = "9F2A133A77AC3ADA8B902FC8E8A67F422B15A3DE"
      cert_valid_from     = "2025-07-31"
      cert_valid_to       = "2026-07-31"

      country             = "CA"
      state               = "Ontario"
      locality            = "Stittsville"
      email               = "???"
      rdn_serial_number   = "1247135-3"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "16:a7:da:92:27:18:50:74:9d:3d:d6:96:d5:87:4b:7e"
      )
}

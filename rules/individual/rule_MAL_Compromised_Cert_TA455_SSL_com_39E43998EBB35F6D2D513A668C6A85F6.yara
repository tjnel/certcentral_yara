import "pe"

rule MAL_Compromised_Cert_TA455_SSL_com_39E43998EBB35F6D2D513A668C6A85F6 {
   meta:
      description         = "Detects TA455 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-16"
      version             = "1.0"

      hash                = "129a40e38ef075c7d33d8517b268eb023093c765a32e406b58f39fab6cc6a040"
      malware             = "TA455"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Flyland Software"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "39:e4:39:98:eb:b3:5f:6d:2d:51:3a:66:8c:6a:85:f6"
      cert_thumbprint     = "E2BD13F8E92144DFC6944DA1EF02EE6838A30F6A"
      cert_valid_from     = "2025-04-16"
      cert_valid_to       = "2026-04-16"

      country             = "FR"
      state               = "???"
      locality            = "Paris"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "39:e4:39:98:eb:b3:5f:6d:2d:51:3a:66:8c:6a:85:f6"
      )
}

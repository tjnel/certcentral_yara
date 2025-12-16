import "pe"

rule MAL_Compromised_Cert_TA455_SSL_com_2848CDE84DCF101BBF54EAB1D5F3C55E {
   meta:
      description         = "Detects TA455 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-09"
      version             = "1.0"

      hash                = "0e4ff052250ade1edaab87de194e87a9afeff903695799bcbc3571918b131100"
      malware             = "TA455"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Insight Digital B.V."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "28:48:cd:e8:4d:cf:10:1b:bf:54:ea:b1:d5:f3:c5:5e"
      cert_thumbprint     = "639D1C9473B7B289CEE9853A991A8B55A8B36168"
      cert_valid_from     = "2025-07-09"
      cert_valid_to       = "2026-07-09"

      country             = "NL"
      state               = "South Holland"
      locality            = "Groot-Ammers"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "28:48:cd:e8:4d:cf:10:1b:bf:54:ea:b1:d5:f3:c5:5e"
      )
}

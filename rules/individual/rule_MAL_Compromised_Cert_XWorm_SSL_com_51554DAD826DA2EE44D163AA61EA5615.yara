import "pe"

rule MAL_Compromised_Cert_XWorm_SSL_com_51554DAD826DA2EE44D163AA61EA5615 {
   meta:
      description         = "Detects XWorm with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-28"
      version             = "1.0"

      hash                = "578036563087d55a9ebd0d4e82495bffb08a3c914d52f3f01a25951bb0539f7f"
      malware             = "XWorm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PEDRO HENRIQUE SILVA DE JESUS 13812209756"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "51:55:4d:ad:82:6d:a2:ee:44:d1:63:aa:61:ea:56:15"
      cert_thumbprint     = "00A98A0118CF09C528DE9E3FC75C7A69DA0E2A6A"
      cert_valid_from     = "2024-11-28"
      cert_valid_to       = "2025-11-28"

      country             = "BR"
      state               = "Rio de Janeiro"
      locality            = "Rio de Janeiro"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "51:55:4d:ad:82:6d:a2:ee:44:d1:63:aa:61:ea:56:15"
      )
}

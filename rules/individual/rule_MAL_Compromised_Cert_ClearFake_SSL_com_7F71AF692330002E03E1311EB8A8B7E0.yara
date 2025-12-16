import "pe"

rule MAL_Compromised_Cert_ClearFake_SSL_com_7F71AF692330002E03E1311EB8A8B7E0 {
   meta:
      description         = "Detects ClearFake with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-04"
      version             = "1.0"

      hash                = "1486747dc29892c549c81cacdf397a8ac00b4aff52cdd5509d5aed3f8036b352"
      malware             = "ClearFake"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hebei Yingtong Pipeline Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7f:71:af:69:23:30:00:2e:03:e1:31:1e:b8:a8:b7:e0"
      cert_thumbprint     = "B8B63B45242CF37561729AA4CB601CFE67E9DBFA"
      cert_valid_from     = "2024-07-04"
      cert_valid_to       = "2025-07-04"

      country             = "CN"
      state               = "Hebei"
      locality            = "Cangzhou"
      email               = "???"
      rdn_serial_number   = "91130900335872388P"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7f:71:af:69:23:30:00:2e:03:e1:31:1e:b8:a8:b7:e0"
      )
}

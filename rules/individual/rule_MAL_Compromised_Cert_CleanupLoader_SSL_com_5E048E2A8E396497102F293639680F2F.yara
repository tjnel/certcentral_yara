import "pe"

rule MAL_Compromised_Cert_CleanupLoader_SSL_com_5E048E2A8E396497102F293639680F2F {
   meta:
      description         = "Detects CleanupLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-13"
      version             = "1.0"

      hash                = "776aee817254e9aafee52099d51bc45cdea3a0a7d70c88fb9445fcddb808ba3d"
      malware             = "CleanupLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INSURE AND PROTECT LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5e:04:8e:2a:8e:39:64:97:10:2f:29:36:39:68:0f:2f"
      cert_thumbprint     = "9898AB0AC82C256316C1E7E2735E74E29352704B"
      cert_valid_from     = "2023-09-13"
      cert_valid_to       = "2024-09-12"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "12573142"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5e:04:8e:2a:8e:39:64:97:10:2f:29:36:39:68:0f:2f"
      )
}

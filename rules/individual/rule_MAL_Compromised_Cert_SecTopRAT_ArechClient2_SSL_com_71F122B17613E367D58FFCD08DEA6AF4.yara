import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_SSL_com_71F122B17613E367D58FFCD08DEA6AF4 {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-20"
      version             = "1.0"

      hash                = "aebfc3d84cf3a4e825aea9e2ea1853e622142223d3b4d66dcd6b753ddce1244a"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Mosak Soft Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "71:f1:22:b1:76:13:e3:67:d5:8f:fc:d0:8d:ea:6a:f4"
      cert_thumbprint     = "320ECD6F82F874CDC0CDD2EAEF8164298E9943F9"
      cert_valid_from     = "2024-08-20"
      cert_valid_to       = "2025-08-20"

      country             = "NZ"
      state               = "Auckland Region"
      locality            = "Auckland"
      email               = "???"
      rdn_serial_number   = "8177681"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "71:f1:22:b1:76:13:e3:67:d5:8f:fc:d0:8d:ea:6a:f4"
      )
}

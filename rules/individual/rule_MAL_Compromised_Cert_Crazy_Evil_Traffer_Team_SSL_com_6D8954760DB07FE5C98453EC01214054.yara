import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_SSL_com_6D8954760DB07FE5C98453EC01214054 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-03"
      version             = "1.0"

      hash                = "68af982a554ee0293d98e7b3bbc8bfd2d1c472a5736bd1045ce75d08554aa778"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "PBT IT LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6d:89:54:76:0d:b0:7f:e5:c9:84:53:ec:01:21:40:54"
      cert_thumbprint     = "15DF176B9F9CE31AB237F39AC625FC2B89935DF5"
      cert_valid_from     = "2025-06-03"
      cert_valid_to       = "2026-06-03"

      country             = "NZ"
      state               = "Auckland Region"
      locality            = "Auckland"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6d:89:54:76:0d:b0:7f:e5:c9:84:53:ec:01:21:40:54"
      )
}

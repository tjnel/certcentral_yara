import "pe"

rule MAL_Compromised_Cert_CrazyEvilTrafferTeam_SSL_com_5DFD0E9D2EB85BE5912CCB6EFE551AB9 {
   meta:
      description         = "Detects CrazyEvilTrafferTeam with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-04"
      version             = "1.0"

      hash                = "ae111d30ea9abe210c4451982a3ea67e99e36cb37e534d133d6bc603afacbea7"
      malware             = "CrazyEvilTrafferTeam"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Richester Business Network Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5d:fd:0e:9d:2e:b8:5b:e5:91:2c:cb:6e:fe:55:1a:b9"
      cert_thumbprint     = "1A90B2BEF92A6E67D4542EBE9D0B28B550AB720D"
      cert_valid_from     = "2025-09-04"
      cert_valid_to       = "2026-09-01"

      country             = "CA"
      state               = "Alberta"
      locality            = "Calgary"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5d:fd:0e:9d:2e:b8:5b:e5:91:2c:cb:6e:fe:55:1a:b9"
      )
}

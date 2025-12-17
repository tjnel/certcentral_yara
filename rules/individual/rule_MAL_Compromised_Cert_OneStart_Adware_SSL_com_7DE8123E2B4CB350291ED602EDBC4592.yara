import "pe"

rule MAL_Compromised_Cert_OneStart_Adware_SSL_com_7DE8123E2B4CB350291ED602EDBC4592 {
   meta:
      description         = "Detects OneStart Adware with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-28"
      version             = "1.0"

      hash                = "469960964daf6666231f379604cb0cbd536b277bdb595c7ded9e8147278ba5ea"
      malware             = "OneStart Adware"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Apollo Technologies Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7d:e8:12:3e:2b:4c:b3:50:29:1e:d6:02:ed:bc:45:92"
      cert_thumbprint     = "EB5A7872B0563D261362F00BC6AF0AFC36877A89"
      cert_valid_from     = "2023-07-28"
      cert_valid_to       = "2026-07-25"

      country             = "PA"
      state               = "???"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155722923"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7d:e8:12:3e:2b:4c:b3:50:29:1e:d6:02:ed:bc:45:92"
      )
}

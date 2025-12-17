import "pe"

rule MAL_Compromised_Cert_QuirkyLoader_SSL_com_5C06E4EE4EA78E8F24B10D1238DAAB64 {
   meta:
      description         = "Detects QuirkyLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-30"
      version             = "1.0"

      hash                = "f470ab8df8dc7764cb726c85d9a6f5daadca98d45f34bff992a563754b484b93"
      malware             = "QuirkyLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Universal Vision Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5c:06:e4:ee:4e:a7:8e:8f:24:b1:0d:12:38:da:ab:64"
      cert_thumbprint     = "ED4230930868AF4447D4A6C844D1C41E90EAC83E"
      cert_valid_from     = "2025-09-30"
      cert_valid_to       = "2026-09-30"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5c:06:e4:ee:4e:a7:8e:8f:24:b1:0d:12:38:da:ab:64"
      )
}

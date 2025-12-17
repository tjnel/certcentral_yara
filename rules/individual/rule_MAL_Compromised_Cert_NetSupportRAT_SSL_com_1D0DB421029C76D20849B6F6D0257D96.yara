import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_SSL_com_1D0DB421029C76D20849B6F6D0257D96 {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-30"
      version             = "1.0"

      hash                = "76053660a8f03b6cf58158e7db53052dc5ecc0f8d0cdd3c5237cd976cb6fd2f7"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Ek-Market Ab Quercus Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1d:0d:b4:21:02:9c:76:d2:08:49:b6:f6:d0:25:7d:96"
      cert_thumbprint     = "221B8FCC0917B0EE755616142AF13B826E4AD9B9"
      cert_valid_from     = "2025-09-30"
      cert_valid_to       = "2026-09-30"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Ekenäs"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1d:0d:b4:21:02:9c:76:d2:08:49:b6:f6:d0:25:7d:96"
      )
}

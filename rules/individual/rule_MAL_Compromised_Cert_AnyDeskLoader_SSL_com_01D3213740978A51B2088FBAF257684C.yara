import "pe"

rule MAL_Compromised_Cert_AnyDeskLoader_SSL_com_01D3213740978A51B2088FBAF257684C {
   meta:
      description         = "Detects AnyDeskLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-24"
      version             = "1.0"

      hash                = "14270df7f98777d0c23e0ec2f082eba5e6f7de361574420634edcdbae491f83a"
      malware             = "AnyDeskLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "The file is a loader that downloads a copy of AnyDesk from a shortened URL."

      signer              = "TELESEC AFRICA LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "01:d3:21:37:40:97:8a:51:b2:08:8f:ba:f2:57:68:4c"
      cert_thumbprint     = "8D8A36959B6E29ED20F3147CF3F116779AAE796E"
      cert_valid_from     = "2025-03-24"
      cert_valid_to       = "2026-03-24"

      country             = "KE"
      state               = "???"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "CPR/2010/25799"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "01:d3:21:37:40:97:8a:51:b2:08:8f:ba:f2:57:68:4c"
      )
}

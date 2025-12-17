import "pe"

rule MAL_Compromised_Cert_FriendsCompany_SSL_com_0316079DD29661DAE8A6747BD391F4D6 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-12"
      version             = "1.0"

      hash                = "7adc2e2f2e7e0fac1c063009781343794c7a607943c5d9978d4c8d30ff5cfa01"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Hiveonline ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "03:16:07:9d:d2:96:61:da:e8:a6:74:7b:d3:91:f4:d6"
      cert_thumbprint     = "550251328C671A8B43C56ABE00ACA22A072520EB"
      cert_valid_from     = "2025-06-12"
      cert_valid_to       = "2026-06-12"

      country             = "DK"
      state               = "Capital Region of Denmark"
      locality            = "Copenhagen"
      email               = "???"
      rdn_serial_number   = "38250302"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "03:16:07:9d:d2:96:61:da:e8:a6:74:7b:d3:91:f4:d6"
      )
}

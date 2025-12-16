import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_SSL_com_15460441B271C3759342B930975B90DA {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-28"
      version             = "1.0"

      hash                = "2c7dc1696cb982fa8a08422bc8553babad118cb4e2acb9ae714cf567c7c09c67"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Federico Fiorini Digital Services Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "15:46:04:41:b2:71:c3:75:93:42:b9:30:97:5b:90:da"
      cert_thumbprint     = "26891379A65424914C8FD5B661BE0EA0F3CE229E"
      cert_valid_from     = "2025-04-28"
      cert_valid_to       = "2026-04-28"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "3254215-4"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "15:46:04:41:b2:71:c3:75:93:42:b9:30:97:5b:90:da"
      )
}

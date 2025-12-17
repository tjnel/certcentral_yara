import "pe"

rule MAL_Compromised_Cert_FriendsCompany_SSL_com_39AB793FFA01B5F68E1FA1E1E6F2403D {
   meta:
      description         = "Detects FriendsCompany with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-24"
      version             = "1.0"

      hash                = "f03b5fe265e1e5d85c521a57b6adf89f243b754b96ebf0caccfa48e51d683c5d"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Kdv Software Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "39:ab:79:3f:fa:01:b5:f6:8e:1f:a1:e1:e6:f2:40:3d"
      cert_thumbprint     = "3C92E18C7BDA3BDF158AFDDE6E3616E2135B8E52"
      cert_valid_from     = "2025-01-24"
      cert_valid_to       = "2026-01-24"

      country             = "PL"
      state               = "Mazowieckie"
      locality            = "Zielonka"
      email               = "???"
      rdn_serial_number   = "0000702209"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "39:ab:79:3f:fa:01:b5:f6:8e:1f:a1:e1:e6:f2:40:3d"
      )
}

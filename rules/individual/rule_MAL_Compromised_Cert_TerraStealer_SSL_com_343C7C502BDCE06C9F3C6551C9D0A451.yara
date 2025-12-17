import "pe"

rule MAL_Compromised_Cert_TerraStealer_SSL_com_343C7C502BDCE06C9F3C6551C9D0A451 {
   meta:
      description         = "Detects TerraStealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-23"
      version             = "1.0"

      hash                = "4b6fa036aceb1e2149848ff46c4e1a6a89eee3b7d59769634ce9127fdaa96234"
      malware             = "TerraStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "STERLING SPIRITS COMPANY LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "34:3c:7c:50:2b:dc:e0:6c:9f:3c:65:51:c9:d0:a4:51"
      cert_thumbprint     = "3B6B92AE3EC1CB49095713DDC3806914F9C0CE1A"
      cert_valid_from     = "2024-12-23"
      cert_valid_to       = "2025-12-23"

      country             = "KE"
      state               = "???"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "CPR/2010/25485"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "34:3c:7c:50:2b:dc:e0:6c:9f:3c:65:51:c9:d0:a4:51"
      )
}

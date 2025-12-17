import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_330003058784DB376DA2248929000000030587 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-29"
      version             = "1.0"

      hash                = "2a175377b452d24abc1c0483bdf98ea6a44e0420db40a797bbd5f6599505c6aa"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:03:05:87:84:db:37:6d:a2:24:89:29:00:00:00:03:05:87"
      cert_thumbprint     = "22A121FFD35765085BE0B38029407B942F0F285A"
      cert_valid_from     = "2025-05-29"
      cert_valid_to       = "2025-06-01"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:03:05:87:84:db:37:6d:a2:24:89:29:00:00:00:03:05:87"
      )
}

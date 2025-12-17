import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_SSL_com_31F2B8DF98119016D60A1DFD656FE40E {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-29"
      version             = "1.0"

      hash                = "b9576867738918a2d065dfa9b78ec9657a2a8a7464d786d836bfdc843d43a812"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "SMI Consulting GmbH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "31:f2:b8:df:98:11:90:16:d6:0a:1d:fd:65:6f:e4:0e"
      cert_thumbprint     = "FF5156C6FE68B5C49035DE4F0DDAD5322467166A"
      cert_valid_from     = "2025-09-29"
      cert_valid_to       = "2026-08-19"

      country             = "AT"
      state               = "Wien"
      locality            = "Wien"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "31:f2:b8:df:98:11:90:16:d6:0a:1d:fd:65:6f:e4:0e"
      )
}

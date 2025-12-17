import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_36C5DB58902613F6221E388B95DCF8A4 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-17"
      version             = "1.0"

      hash                = "6d7fddff5b509fdd5372caa740e2227a8b0be2db1a7e9a59e16873ffc4f351e4"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "GINA International s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "36:c5:db:58:90:26:13:f6:22:1e:38:8b:95:dc:f8:a4"
      cert_thumbprint     = "8CBA06BD53411043CB7DF4F6ACFE7856D9440815"
      cert_valid_from     = "2024-07-17"
      cert_valid_to       = "2025-07-17"

      country             = "CZ"
      state               = "???"
      locality            = "Brno"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "36:c5:db:58:90:26:13:f6:22:1e:38:8b:95:dc:f8:a4"
      )
}

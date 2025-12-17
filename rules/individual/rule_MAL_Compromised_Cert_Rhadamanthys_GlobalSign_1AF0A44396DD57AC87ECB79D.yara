import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_1AF0A44396DD57AC87ECB79D {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-15"
      version             = "1.0"

      hash                = "fac7f1a54eef98830ecbd25fef364695b8afd9e255dcc19702dac84ee526c5ca"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Lion Software, LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1a:f0:a4:43:96:dd:57:ac:87:ec:b7:9d"
      cert_thumbprint     = "A243692CD9205CFE32BEEF144B7D84350F3AA0E6"
      cert_valid_from     = "2024-10-15"
      cert_valid_to       = "2025-10-16"

      country             = "US"
      state               = "Alabama"
      locality            = "Centre"
      email               = "???"
      rdn_serial_number   = "000-541-240"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1a:f0:a4:43:96:dd:57:ac:87:ec:b7:9d"
      )
}

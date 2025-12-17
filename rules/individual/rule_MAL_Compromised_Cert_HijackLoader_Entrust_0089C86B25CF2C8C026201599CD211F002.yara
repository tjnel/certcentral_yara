import "pe"

rule MAL_Compromised_Cert_HijackLoader_Entrust_0089C86B25CF2C8C026201599CD211F002 {
   meta:
      description         = "Detects HijackLoader with compromised cert (Entrust)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-08"
      version             = "1.0"

      hash                = "5c1917c63fc09983d5f31cb7278122405f28364b93956a96cf635e52f7381f2a"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Software Support ApS"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "00:89:c8:6b:25:cf:2c:8c:02:62:01:59:9c:d2:11:f0:02"
      cert_thumbprint     = "88331C66A0AEBECE198DDB48E57931AC8047A53A"
      cert_valid_from     = "2024-11-08"
      cert_valid_to       = "2025-11-08"

      country             = "DK"
      state               = "???"
      locality            = "København N"
      email               = "???"
      rdn_serial_number   = "37790672"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "00:89:c8:6b:25:cf:2c:8c:02:62:01:59:9c:d2:11:f0:02"
      )
}

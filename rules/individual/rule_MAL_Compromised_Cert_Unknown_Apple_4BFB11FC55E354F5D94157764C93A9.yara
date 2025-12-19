import "pe"

rule MAL_Compromised_Cert_Unknown_Apple_4BFB11FC55E354F5D94157764C93A9 {
   meta:
      description         = "Detects Unknown with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-03"
      version             = "1.0"

      hash                = "bc4c1cd39d60c29959a4909a5ff71db566a06d62d75405a37e710daca2d4771f"
      malware             = "Unknown"
      malware_type        = "Trojan"
      malware_notes       = "Identified by VirusTotal's code insights as a trojan. Discussed by L0psec regarding the cert being used by the jailbreaking community: https://x.com/L0Psec/status/1999143566883398078"

      signer              = "HDFC Bank Limited"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "4b:fb:11:fc:55:e3:54:f5:d9:41:57:76:4c:93:a9"
      cert_thumbprint     = "155D172238A78B4A467B686913AD5041AB9543CE"
      cert_valid_from     = "2025-01-03"
      cert_valid_to       = "2028-01-03"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "4b:fb:11:fc:55:e3:54:f5:d9:41:57:76:4c:93:a9"
      )
}

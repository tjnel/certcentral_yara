import "pe"

rule MAL_Compromised_Cert_Xtract_trojan_productivity_tool_GlobalSign_17B85C86D451E2EAEE121A47 {
   meta:
      description         = "Detects Xtract,trojan productivity tool with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-22"
      version             = "1.0"

      hash                = "2063c4a79c44b398869e1296447f5e687d428113f62f1f22665d8bb5d9c9dda6"
      malware             = "Xtract,trojan productivity tool"
      malware_type        = "Trojan"
      malware_notes       = "Trojan productivity tool"

      signer              = "BITTERN SKY LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "17:b8:5c:86:d4:51:e2:ea:ee:12:1a:47"
      cert_thumbprint     = "EB855C3C179411119FF93093593AA6FA9DC95178"
      cert_valid_from     = "2025-05-22"
      cert_valid_to       = "2026-05-23"

      country             = "IL"
      state               = "Central District"
      locality            = "Ra'anana"
      email               = "contactus@bitternskyltd.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "17:b8:5c:86:d4:51:e2:ea:ee:12:1a:47"
      )
}

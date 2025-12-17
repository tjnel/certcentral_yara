import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_23639379C01B600659A5D5B3 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-26"
      version             = "1.0"

      hash                = "56180ce6f73b08ad79fba8cf128c9851724485c5445b348eb4e67a3ae2bccd17"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LeYao Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "23:63:93:79:c0:1b:60:06:59:a5:d5:b3"
      cert_thumbprint     = "A70779EB04A174FAECEBA8CC216074ACDF872975"
      cert_valid_from     = "2024-11-26"
      cert_valid_to       = "2025-11-26"

      country             = "CN"
      state               = "Hebei"
      locality            = "Qinhuangdao"
      email               = "???"
      rdn_serial_number   = "91130302MA0G33CQ5Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "23:63:93:79:c0:1b:60:06:59:a5:d5:b3"
      )
}

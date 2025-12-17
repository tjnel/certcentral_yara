import "pe"

rule MAL_Compromised_Cert_DarkGate_GlobalSign_0AEE6C4FC643B7B43C38160B {
   meta:
      description         = "Detects DarkGate with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-26"
      version             = "1.0"

      hash                = "633cbe5aeee1f6ca06e39ace57475ab53f5b5604fd06eb2a4d29d9c428324597"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "Inoellact EloubantTech Optimization Information Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0a:ee:6c:4f:c6:43:b7:b4:3c:38:16:0b"
      cert_thumbprint     = "F76DC22EF14C926A7FE5F356C12B205DF79553A5"
      cert_valid_from     = "2024-01-26"
      cert_valid_to       = "2025-01-26"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Foshan"
      email               = "???"
      rdn_serial_number   = "91440605MACRJLFMXL"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0a:ee:6c:4f:c6:43:b7:b4:3c:38:16:0b"
      )
}

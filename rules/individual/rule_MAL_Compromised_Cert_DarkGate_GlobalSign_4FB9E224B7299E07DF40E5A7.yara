import "pe"

rule MAL_Compromised_Cert_DarkGate_GlobalSign_4FB9E224B7299E07DF40E5A7 {
   meta:
      description         = "Detects DarkGate with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-22"
      version             = "1.0"

      hash                = "0130e9d398cc202f042ac8c8712712950b5e29842993260517a79b983e8f090a"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "PFO GROUP LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4f:b9:e2:24:b7:29:9e:07:df:40:e5:a7"
      cert_thumbprint     = "0D06E3B818564114EE679A11BA15E686D3F4593F"
      cert_valid_from     = "2023-08-22"
      cert_valid_to       = "2024-06-30"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1167746512735"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4f:b9:e2:24:b7:29:9e:07:df:40:e5:a7"
      )
}

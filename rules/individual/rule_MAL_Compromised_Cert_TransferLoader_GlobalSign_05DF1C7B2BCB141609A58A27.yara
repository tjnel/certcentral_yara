import "pe"

rule MAL_Compromised_Cert_TransferLoader_GlobalSign_05DF1C7B2BCB141609A58A27 {
   meta:
      description         = "Detects TransferLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-27"
      version             = "1.0"

      hash                = "21a262cab858944181d01b1bdeba51c8f4dab8e4f064a12c614eb89c294d94c5"
      malware             = "TransferLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was disguised as a resume and a PDF. It uses a PDF as a decoy. See this blog for more details on the malware family: https://www.zscaler.com/blogs/security-research/technical-analysis-transferloader"

      signer              = "LLC Okrasheno"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "05:df:1c:7b:2b:cb:14:16:09:a5:8a:27"
      cert_thumbprint     = "3055ED9CE7BEFBD520146CE08AE4DE65EA826A2D"
      cert_valid_from     = "2025-05-27"
      cert_valid_to       = "2026-05-28"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "05:df:1c:7b:2b:cb:14:16:09:a5:8a:27"
      )
}

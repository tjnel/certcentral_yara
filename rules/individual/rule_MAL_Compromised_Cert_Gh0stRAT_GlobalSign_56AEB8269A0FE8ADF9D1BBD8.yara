import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_GlobalSign_56AEB8269A0FE8ADF9D1BBD8 {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-24"
      version             = "1.0"

      hash                = "d8655cb920dff79d3fc2006247925cf66c198595ed3e496218a5b24c2bb1080f"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UCon Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "56:ae:b8:26:9a:0f:e8:ad:f9:d1:bb:d8"
      cert_thumbprint     = "064F423FCB68FCF5246A5F379F2405D1CEB789C0"
      cert_valid_from     = "2025-04-24"
      cert_valid_to       = "2026-04-25"

      country             = "CN"
      state               = "GUANGDONG"
      locality            = "SHENZHEN"
      email               = "???"
      rdn_serial_number   = "914403003350884898"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "56:ae:b8:26:9a:0f:e8:ad:f9:d1:bb:d8"
      )
}

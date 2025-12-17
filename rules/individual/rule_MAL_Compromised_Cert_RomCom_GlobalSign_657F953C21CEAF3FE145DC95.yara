import "pe"

rule MAL_Compromised_Cert_RomCom_GlobalSign_657F953C21CEAF3FE145DC95 {
   meta:
      description         = "Detects RomCom with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-20"
      version             = "1.0"

      hash                = "8b683ed0d1cd0139093e21889be077d0e4e50e7adaf638b56e2077df5c6eda4b"
      malware             = "RomCom"
      malware_type        = "Backdoor"
      malware_notes       = "The malware is often disguised as a PDF and will launch an unrelated application when ran. See this for more details: https://www.bridewell.com/insights/blogs/detail/operation-deceptive-prospect-romcom-targeting-uk-organisations-through-customer-feedback-portals"

      signer              = "GMC CONSTRUCTION AND TRADING COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 CodeSigning CA 2020"
      cert_serial         = "65:7f:95:3c:21:ce:af:3f:e1:45:dc:95"
      cert_thumbprint     = "C8CBB1EAAE2FD97FA811ECE21655E2CB96510255"
      cert_valid_from     = "2025-02-20"
      cert_valid_to       = "2026-02-21"

      country             = "VN"
      state               = "Ninh Binh"
      locality            = "Ninh Binh"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 CodeSigning CA 2020" and
         sig.serial == "65:7f:95:3c:21:ce:af:3f:e1:45:dc:95"
      )
}

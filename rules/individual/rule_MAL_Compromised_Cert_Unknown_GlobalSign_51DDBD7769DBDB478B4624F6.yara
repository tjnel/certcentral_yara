import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_51DDBD7769DBDB478B4624F6 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-01"
      version             = "1.0"

      hash                = "4dfbcca0441d00cab3298c404fbad7949979b697aa8cf685835d87a808d91d5f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UBUNTU CONSORTIUM (PTY) LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "51:dd:bd:77:69:db:db:47:8b:46:24:f6"
      cert_thumbprint     = "90B9F6BB53C963E693A178EFC4B889DA5F8390AD"
      cert_valid_from     = "2025-08-01"
      cert_valid_to       = "2026-08-02"

      country             = "ZA"
      state               = "Gauteng"
      locality            = "Benoni"
      email               = "ndulahena@outlook.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "51:dd:bd:77:69:db:db:47:8b:46:24:f6"
      )
}

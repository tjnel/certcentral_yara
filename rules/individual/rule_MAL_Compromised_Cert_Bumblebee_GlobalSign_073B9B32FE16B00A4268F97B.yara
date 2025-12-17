import "pe"

rule MAL_Compromised_Cert_Bumblebee_GlobalSign_073B9B32FE16B00A4268F97B {
   meta:
      description         = "Detects Bumblebee with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-22"
      version             = "1.0"

      hash                = "76ea5c5bd76941aae78a9212929db83a8975260265c58dea38ddf20e3c35ce10"
      malware             = "Bumblebee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Invest Center"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "07:3b:9b:32:fe:16:b0:0a:42:68:f9:7b"
      cert_thumbprint     = "4AB277F472FB6FD4FA155BF314E2F93EE3A308FE"
      cert_valid_from     = "2025-05-22"
      cert_valid_to       = "2026-05-23"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1147746292693"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "07:3b:9b:32:fe:16:b0:0a:42:68:f9:7b"
      )
}

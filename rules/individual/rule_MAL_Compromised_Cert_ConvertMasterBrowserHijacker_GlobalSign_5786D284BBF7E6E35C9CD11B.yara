import "pe"

rule MAL_Compromised_Cert_ConvertMasterBrowserHijacker_GlobalSign_5786D284BBF7E6E35C9CD11B {
   meta:
      description         = "Detects ConvertMasterBrowserHijacker with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-20"
      version             = "1.0"

      hash                = "d0c7471c7950b2f80dbf92f929dfb0f10d518b551b326e56e9b2870de90196f3"
      malware             = "ConvertMasterBrowserHijacker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TECHNODENIS LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "57:86:d2:84:bb:f7:e6:e3:5c:9c:d1:1b"
      cert_thumbprint     = "D8263A1EA0C4D119C5346E1B26200377283774F4"
      cert_valid_from     = "2025-01-20"
      cert_valid_to       = "2026-04-27"

      country             = "IL"
      state               = "Central District"
      locality            = "Ra'anana"
      email               = "contactus@technodenisltd.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "57:86:d2:84:bb:f7:e6:e3:5c:9c:d1:1b"
      )
}

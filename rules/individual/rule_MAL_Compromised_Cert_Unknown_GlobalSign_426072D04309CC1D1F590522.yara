import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_426072D04309CC1D1F590522 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-16"
      version             = "1.0"

      hash                = "5c4253a21c527794b0f6970a19f7aeed5d3be4cefcdf35a29ef23e6f0123cfc5"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Info Tech Globalcorp Limited"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "42:60:72:d0:43:09:cc:1d:1f:59:05:22"
      cert_thumbprint     = "5e832d219ddb0fa979838229ca5c2cbae27a11b9909a10350c78ff599f5aef3e"
      cert_valid_from     = "2024-12-16"
      cert_valid_to       = "2025-12-17"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Vancouver"
      email               = "???"
      rdn_serial_number   = "1348599-4"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "42:60:72:d0:43:09:cc:1d:1f:59:05:22"
      )
}

import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_2A074CF080DFCB5586832383 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-06"
      version             = "1.0"

      hash                = "4d2a12f2232a7833b0842560d11682a25aeca95d8bca92014ce12698c2180dbe"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Changzhou Jintan Bangke Network Info. Tech. Service Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2a:07:4c:f0:80:df:cb:55:86:83:23:83"
      cert_thumbprint     = "DBA4616F360ECAE74C3FCF0AFEFF59E19FF49FD2"
      cert_valid_from     = "2023-04-06"
      cert_valid_to       = "2026-04-06"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Changzhou"
      email               = "???"
      rdn_serial_number   = "91320413MA1P3Q80X0"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2a:07:4c:f0:80:df:cb:55:86:83:23:83"
      )
}

import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_24123F33DF7CA692F2F732BC {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-19"
      version             = "1.0"

      hash                = "b0da9e82ec888ecad575e2b027bad8d040180afb6116fc778531db84a3843e3c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HOUSE 2 HOME, INC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "24:12:3f:33:df:7c:a6:92:f2:f7:32:bc"
      cert_thumbprint     = "7BAFC50D7E39C58FC2BDE9A28E30CA8937EA8F58"
      cert_valid_from     = "2024-07-19"
      cert_valid_to       = "2025-07-20"

      country             = "US"
      state               = "Utah"
      locality            = "Lehi"
      email               = "???"
      rdn_serial_number   = "9481125-0142"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "24:12:3f:33:df:7c:a6:92:f2:f7:32:bc"
      )
}

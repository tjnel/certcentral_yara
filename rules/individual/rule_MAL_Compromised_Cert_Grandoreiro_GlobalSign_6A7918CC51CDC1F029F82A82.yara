import "pe"

rule MAL_Compromised_Cert_Grandoreiro_GlobalSign_6A7918CC51CDC1F029F82A82 {
   meta:
      description         = "Detects Grandoreiro with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-05"
      version             = "1.0"

      hash                = "305e220e1f1cb506c32bb509f246515e3cba7ec1dabae95298f358d26654bfa6"
      malware             = "Grandoreiro"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Defz Software Solutions GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6a:79:18:cc:51:cd:c1:f0:29:f8:2a:82"
      cert_thumbprint     = "a8909525c86ca94940682746830598d7b763cbefb0d8e61a2763f60fba52077f"
      cert_valid_from     = "2023-12-05"
      cert_valid_to       = "2024-12-05"

      country             = "AT"
      state               = "Steiermark"
      locality            = "Ludersdorf-Wilfersdorf"
      email               = "admin@defzsoftwaresolutions.com"
      rdn_serial_number   = "597406p"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6a:79:18:cc:51:cd:c1:f0:29:f8:2a:82"
      )
}

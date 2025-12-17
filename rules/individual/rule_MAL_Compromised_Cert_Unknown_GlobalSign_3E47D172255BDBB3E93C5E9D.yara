import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_3E47D172255BDBB3E93C5E9D {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-26"
      version             = "1.0"

      hash                = "db78fca7ed503d6fdd667e1eaa26a3a4cf2c4131b911084f2961556c50689253"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HUDDA FOODS (SMC-PRIVATE) LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3e:47:d1:72:25:5b:db:b3:e9:3c:5e:9d"
      cert_thumbprint     = "02FED651B2EADA8963E95644141336451C2337A7"
      cert_valid_from     = "2024-04-26"
      cert_valid_to       = "2025-04-27"

      country             = "PK"
      state               = "Punjab"
      locality            = "Multan"
      email               = "huddafoods@gmail.com"
      rdn_serial_number   = "0168969"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3e:47:d1:72:25:5b:db:b3:e9:3c:5e:9d"
      )
}

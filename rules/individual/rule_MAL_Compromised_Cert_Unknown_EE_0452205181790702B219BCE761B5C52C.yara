import "pe"

rule MAL_Compromised_Cert_Unknown_EE_0452205181790702B219BCE761B5C52C {
   meta:
      description         = "Detects Unknown with compromised cert (EE)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-08"
      version             = "1.0"

      hash                = "d4e1b6c2cd19faf9ff1cd489491749529449304210386630167a3dec995c9b23"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "www.huixineap.com"
      cert_issuer_short   = "EE"
      cert_issuer         = "Encryption Everywhere DV TLS CA - G2"
      cert_serial         = "04:52:20:51:81:79:07:02:b2:19:bc:e7:61:b5:c5:2c"
      cert_thumbprint     = "7FCCB05B2E1786FC7E840A2E94614B1AB5A678A1"
      cert_valid_from     = "2025-04-08"
      cert_valid_to       = "2025-07-07"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Encryption Everywhere DV TLS CA - G2" and
         sig.serial == "04:52:20:51:81:79:07:02:b2:19:bc:e7:61:b5:c5:2c"
      )
}

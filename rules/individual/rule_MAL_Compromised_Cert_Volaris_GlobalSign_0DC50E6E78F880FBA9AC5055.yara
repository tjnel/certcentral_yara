import "pe"

rule MAL_Compromised_Cert_Volaris_GlobalSign_0DC50E6E78F880FBA9AC5055 {
   meta:
      description         = "Detects Volaris with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-04"
      version             = "1.0"

      hash                = "edbf9a6f32030a6d785c60a0c3600d38d316b42d237aedb43e81bc2ceb372967"
      malware             = "Volaris"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MEDIA4YU GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0d:c5:0e:6e:78:f8:80:fb:a9:ac:50:55"
      cert_thumbprint     = "71248E8575D821CDA8419FEAA11E8DA328C57F75"
      cert_valid_from     = "2025-07-04"
      cert_valid_to       = "2026-07-05"

      country             = "AT"
      state               = "Wien"
      locality            = "Wien"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0d:c5:0e:6e:78:f8:80:fb:a9:ac:50:55"
      )
}

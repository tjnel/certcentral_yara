import "pe"

rule MAL_Compromised_Cert_RUS_51_GlobalSign_44B8667357BB95651D61D061 {
   meta:
      description         = "Detects RUS-51 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-19"
      version             = "1.0"

      hash                = "9ebfe694914d337304edded8b6406bd3fbff1d4ee110ef3a8bf95c3fb5de7c38"
      malware             = "RUS-51"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Cascade Tech-Trek Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "44:b8:66:73:57:bb:95:65:1d:61:d0:61"
      cert_thumbprint     = "9F24096B07D3AC87E48DB7D37CC70F269AE643A3"
      cert_valid_from     = "2024-11-19"
      cert_valid_to       = "2025-11-20"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Burnaby"
      email               = "???"
      rdn_serial_number   = "771956-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "44:b8:66:73:57:bb:95:65:1d:61:d0:61"
      )
}

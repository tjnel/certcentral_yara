import "pe"

rule MAL_Compromised_Cert_Volaris_GlobalSign_5FF0C92F07F4C38EDF789E75 {
   meta:
      description         = "Detects Volaris with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-02"
      version             = "1.0"

      hash                = "86f543ef0ab49d6c3ed3d6c55b5ff2371931b55b7e569233e11ed2ee1dcdcd4d"
      malware             = "Volaris"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AN Marketing B.V."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5f:f0:c9:2f:07:f4:c3:8e:df:78:9e:75"
      cert_thumbprint     = "88719D6BDBE9ABC3CD99828F040AAF9CD1688A9D"
      cert_valid_from     = "2025-07-02"
      cert_valid_to       = "2026-07-03"

      country             = "NL"
      state               = "Noord-Holland"
      locality            = "Amsterdam-Duivendrecht"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5f:f0:c9:2f:07:f4:c3:8e:df:78:9e:75"
      )
}

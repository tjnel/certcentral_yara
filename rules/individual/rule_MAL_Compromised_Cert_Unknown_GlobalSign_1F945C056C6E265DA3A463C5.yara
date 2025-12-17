import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_1F945C056C6E265DA3A463C5 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-02"
      version             = "1.0"

      hash                = "a0ad640511291000117b8c53b598f50a7235e77ac8c8db5b1b0ea93cca7239f4"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chengdu Lingxu Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1f:94:5c:05:6c:6e:26:5d:a3:a4:63:c5"
      cert_thumbprint     = "AD511AF5F713F129A554BD50609204D46EC726CF"
      cert_valid_from     = "2025-09-02"
      cert_valid_to       = "2026-09-03"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1f:94:5c:05:6c:6e:26:5d:a3:a4:63:c5"
      )
}

import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_5AE7F3327E5B41A9948647E8 {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-24"
      version             = "1.0"

      hash                = "3af32eeede84d9ab70ce15ef51fa2bd7da42224537551410f565d1ec3b22b005"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "APPEX FINVEST PVT LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5a:e7:f3:32:7e:5b:41:a9:94:86:47:e8"
      cert_thumbprint     = "B2EC5F5CDD0FC121EA93A4724A5957B7F7997129"
      cert_valid_from     = "2025-07-24"
      cert_valid_to       = "2026-07-25"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "navneetmalpani95@gmail.com"
      rdn_serial_number   = "U65910RJ1995PTC009975"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5a:e7:f3:32:7e:5b:41:a9:94:86:47:e8"
      )
}

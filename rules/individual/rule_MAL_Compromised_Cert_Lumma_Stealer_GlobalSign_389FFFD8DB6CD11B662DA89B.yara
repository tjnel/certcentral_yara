import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_389FFFD8DB6CD11B662DA89B {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-25"
      version             = "1.0"

      hash                = "3b04fb9046116e28e410d1ee850bcf2a466dd487ba0103cfaa2a023519465518"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "LeYao Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "38:9f:ff:d8:db:6c:d1:1b:66:2d:a8:9b"
      cert_thumbprint     = "EE8747ECD7706F8D40BCC11CC30B833771EB29F0"
      cert_valid_from     = "2024-11-25"
      cert_valid_to       = "2025-11-26"

      country             = "CN"
      state               = "Hebei"
      locality            = "Qinhuangdao"
      email               = "???"
      rdn_serial_number   = "91130302MA0G33CQ5Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "38:9f:ff:d8:db:6c:d1:1b:66:2d:a8:9b"
      )
}

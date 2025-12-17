import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_79994F42444B6F824EDA28D4 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-06-13"
      version             = "1.0"

      hash                = "9167c1b308c3e03a03189f9746e29c8812850c417543a51a250775232b692317"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Chengdu Nuoxin Times Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "79:99:4f:42:44:4b:6f:82:4e:da:28:d4"
      cert_thumbprint     = "EB0D7F2D8B94EE902F73F8BB9D9EC2B1A9CC5546"
      cert_valid_from     = "2023-06-13"
      cert_valid_to       = "2024-06-13"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100MA65214R21"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "79:99:4f:42:44:4b:6f:82:4e:da:28:d4"
      )
}

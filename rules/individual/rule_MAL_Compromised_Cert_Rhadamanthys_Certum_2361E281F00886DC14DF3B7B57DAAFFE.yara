import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_Certum_2361E281F00886DC14DF3B7B57DAAFFE {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-19"
      version             = "1.0"

      hash                = "79212a76f167cf5628a51517f503531daf063d04f0aa5e115b5671121d1ac052"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Qujing Minsi E-commerce Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "23:61:e2:81:f0:08:86:dc:14:df:3b:7b:57:da:af:fe"
      cert_thumbprint     = "49F0B27799AE6EB4E8E20C269AC4A52D7CD0A58F"
      cert_valid_from     = "2025-03-19"
      cert_valid_to       = "2026-03-19"

      country             = "CN"
      state               = "Yunnan"
      locality            = "Qujing"
      email               = "???"
      rdn_serial_number   = "91530302MAC23MFW4X"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "23:61:e2:81:f0:08:86:dc:14:df:3b:7b:57:da:af:fe"
      )
}

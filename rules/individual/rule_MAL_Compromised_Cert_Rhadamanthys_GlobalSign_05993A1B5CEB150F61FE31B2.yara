import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_05993A1B5CEB150F61FE31B2 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-06"
      version             = "1.0"

      hash                = "c50326e6b68e807eaf188f95ff6e2a17df11efbfd0936395b452946085b83fcd"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "MekoGuard Bytemin Information Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "05:99:3a:1b:5c:eb:15:0f:61:fe:31:b2"
      cert_thumbprint     = "281C3D9BFAB4B699BEB0AC7F46D21D5367FDC309"
      cert_valid_from     = "2024-02-06"
      cert_valid_to       = "2025-02-06"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Foshan"
      email               = "???"
      rdn_serial_number   = "91440605MACR7QA22Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "05:99:3a:1b:5c:eb:15:0f:61:fe:31:b2"
      )
}

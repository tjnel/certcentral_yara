import "pe"

rule MAL_Compromised_Cert_FakeComplaint_Certum_3E20454C06263BFEC01DB89A30420456 {
   meta:
      description         = "Detects FakeComplaint with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-09"
      version             = "1.0"

      hash                = "ba8dddf8a49390232d39ff8fba7a24d7ec04ec3a44fb205a50c764d691cdcbf5"
      malware             = "FakeComplaint"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuhan Ronghuixiang Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "3e:20:45:4c:06:26:3b:fe:c0:1d:b8:9a:30:42:04:56"
      cert_thumbprint     = "A7E3C8C3BC37AB63B7605BEFB93FC9B22B811684"
      cert_valid_from     = "2025-10-09"
      cert_valid_to       = "2026-10-09"

      country             = "CN"
      state               = "湖北省"
      locality            = "武汉市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "3e:20:45:4c:06:26:3b:fe:c0:1d:b8:9a:30:42:04:56"
      )
}

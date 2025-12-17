import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Verokey_0CBA02A32BEAB6BFAC34A7511A8B0E22 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Verokey)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-15"
      version             = "1.0"

      hash                = "8b83e7a8abe5779edde1bf8b753cb1aec232d31c1c25e4df69510cf36110bdfe"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "山西荣升源科贸有限公司"
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey High Assurance Secure Code EV"
      cert_serial         = "0c:ba:02:a3:2b:ea:b6:bf:ac:34:a7:51:1a:8b:0e:22"
      cert_thumbprint     = "0d54e75f5be0f646df256098171ee2d1ba24959af6d4008f89aa3397d5aa4f3b"
      cert_valid_from     = "2025-05-15"
      cert_valid_to       = "2026-06-18"

      country             = "CN"
      state               = "山西省"
      locality            = "太原市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Verokey High Assurance Secure Code EV" and
         sig.serial == "0c:ba:02:a3:2b:ea:b6:bf:ac:34:a7:51:1a:8b:0e:22"
      )
}

import "pe"

rule MAL_Compromised_Cert_GodRAT_GlobalSign_476687EF336E88504E5ECE57 {
   meta:
      description         = "Detects GodRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-13"
      version             = "1.0"

      hash                = "db8614ad49b98d8d13d86c1ba74b248c56aead687f9815840e2141e3f6da4450"
      malware             = "GodRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is a never malware with similar developer as Gh0stRAT per Kaspersky: https://securelist.com/godrat/117119/"

      signer              = "金润方舟科技股份有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:66:87:ef:33:6e:88:50:4e:5e:ce:57"
      cert_thumbprint     = "CA3603C36C93AAE2B0EAC87E69DC0F37EB3835E1"
      cert_valid_from     = "2025-08-13"
      cert_valid_to       = "2028-08-13"

      country             = "CN"
      state               = "西藏"
      locality            = "拉萨"
      email               = "???"
      rdn_serial_number   = "91110108753322186R"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:66:87:ef:33:6e:88:50:4e:5e:ce:57"
      )
}

import "pe"

rule MAL_Compromised_Cert_ZhongStealer_Sectigo_22705DBF157ED535146911BAADB3B64A {
   meta:
      description         = "Detects ZhongStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-27"
      version             = "1.0"

      hash                = "a508358a0786ddf2ad9496bb9374d54e71c5044df9c10fe686d43fc70484e54c"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "The malware was downloaded via storage[.]googleapis[.]com/hongkongwork1/ and is disguised as a  image using the filename photo202512176896m.pif, but is an executable."

      signer              = "Weihai Mingjun Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "22:70:5d:bf:15:7e:d5:35:14:69:11:ba:ad:b3:b6:4a"
      cert_thumbprint     = "A947B270081E9E496FF347F4F89FBE3EC9CB2B72"
      cert_valid_from     = "2025-11-27"
      cert_valid_to       = "2026-11-27"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "22:70:5d:bf:15:7e:d5:35:14:69:11:ba:ad:b3:b6:4a"
      )
}

import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_6559999436BD29785FBF07D0F472E994 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-11"
      version             = "1.0"

      hash                = "1052924f914229325270e7cc862ab1ef6fcc73da22dd9afff222f7168b3f8343"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "RichQuest Network Technology Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "65:59:99:94:36:bd:29:78:5f:bf:07:d0:f4:72:e9:94"
      cert_thumbprint     = "59B7B2C37523F7CA057C2CDCC0C6C0482740E9A1"
      cert_valid_from     = "2025-08-11"
      cert_valid_to       = "2026-08-11"

      country             = "CN"
      state               = "Jilin Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "65:59:99:94:36:bd:29:78:5f:bf:07:d0:f4:72:e9:94"
      )
}

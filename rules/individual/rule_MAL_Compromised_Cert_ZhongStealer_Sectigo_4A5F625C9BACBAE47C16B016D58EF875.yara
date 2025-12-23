import "pe"

rule MAL_Compromised_Cert_ZhongStealer_Sectigo_4A5F625C9BACBAE47C16B016D58EF875 {
   meta:
      description         = "Detects ZhongStealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-04"
      version             = "1.0"

      hash                = "962615e17eca365d80c31dd02f2a6c757c073cb24d31d60a1c7818284bd6ca00"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "Malware masquerades as a screenshot, pulls additional stages from legitimate CDN."

      signer              = "Henan Jiyanzhong Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "4a:5f:62:5c:9b:ac:ba:e4:7c:16:b0:16:d5:8e:f8:75"
      cert_thumbprint     = "25069239F52911C80E429AFFA16A7D4FCD65EE54"
      cert_valid_from     = "2025-12-04"
      cert_valid_to       = "2026-12-04"

      country             = "CN"
      state               = "Henan Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91410103MACL9D58X6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "4a:5f:62:5c:9b:ac:ba:e4:7c:16:b0:16:d5:8e:f8:75"
      )
}

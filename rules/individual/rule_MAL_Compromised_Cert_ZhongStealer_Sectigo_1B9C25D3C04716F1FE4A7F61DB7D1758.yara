import "pe"

rule MAL_Compromised_Cert_ZhongStealer_Sectigo_1B9C25D3C04716F1FE4A7F61DB7D1758 {
   meta:
      description         = "Detects ZhongStealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-23"
      version             = "1.0"

      hash                = "70a20ad7ed0d8fbea9d82b585094d58e9113e8e3669ffefd89f5e291bcbedebe"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "Malware masquerades as a photo or screenshot. It then pulls a second stage from legitimate CDN."

      signer              = "Xiamen Boyue Zhiyan Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "1b:9c:25:d3:c0:47:16:f1:fe:4a:7f:61:db:7d:17:58"
      cert_thumbprint     = "22B188A6F3ADC342FBA9F813A626402070F92026"
      cert_valid_from     = "2025-12-23"
      cert_valid_to       = "2026-12-23"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350211MA32PW8L0X"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "1b:9c:25:d3:c0:47:16:f1:fe:4a:7f:61:db:7d:17:58"
      )
}

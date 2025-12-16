import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_5D04BDA411B4EA77878626B9 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-29"
      version             = "1.0"

      hash                = "61b21e5b87e0bd0df0fd822c94a8628355708db6681a46bb7907410152e91dd5"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Dongguan Weibang New Material Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5d:04:bd:a4:11:b4:ea:77:87:86:26:b9"
      cert_thumbprint     = "DBAD42AA98D85A51DD159FB3D3D66A90FB80C8C3"
      cert_valid_from     = "2024-10-29"
      cert_valid_to       = "2025-10-30"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Dongguan"
      email               = "cmengqiu@wbxclkj.com"
      rdn_serial_number   = "91441900MA51LEMH93"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5d:04:bd:a4:11:b4:ea:77:87:86:26:b9"
      )
}

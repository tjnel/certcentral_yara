import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_5E0016A3D3E00463E5BF0753D80CDED2 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-28"
      version             = "1.0"

      hash                = "232d2526c54d5e0795bc7bd077362de5f18d9089d4ae25d6e9a709f2f3ef940a"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gucheng County Qizhishang Trading Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "5e:00:16:a3:d3:e0:04:63:e5:bf:07:53:d8:0c:de:d2"
      cert_thumbprint     = "06E24900DD5E7E64D30AB8288AFA895D2533DFE0"
      cert_valid_from     = "2025-03-28"
      cert_valid_to       = "2026-03-28"

      country             = "CN"
      state               = "Hubei"
      locality            = "Xiangyang"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "5e:00:16:a3:d3:e0:04:63:e5:bf:07:53:d8:0c:de:d2"
      )
}

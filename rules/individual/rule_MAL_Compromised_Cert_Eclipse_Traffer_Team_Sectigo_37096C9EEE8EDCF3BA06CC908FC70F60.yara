import "pe"

rule MAL_Compromised_Cert_Eclipse_Traffer_Team_Sectigo_37096C9EEE8EDCF3BA06CC908FC70F60 {
   meta:
      description         = "Detects Eclipse Traffer Team with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-10"
      version             = "1.0"

      hash                = "4a7d04140e18629886c596b6d558164f172ce1a01511102b956e93c799c4959a"
      malware             = "Eclipse Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hefei Zhouzuan Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "37:09:6c:9e:ee:8e:dc:f3:ba:06:cc:90:8f:c7:0f:60"
      cert_thumbprint     = "5DC8B507DC5A29D7CE4162D77592131EE05BB404"
      cert_valid_from     = "2025-09-10"
      cert_valid_to       = "2026-09-10"

      country             = "CN"
      state               = "Anhui Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "37:09:6c:9e:ee:8e:dc:f3:ba:06:cc:90:8f:c7:0f:60"
      )
}

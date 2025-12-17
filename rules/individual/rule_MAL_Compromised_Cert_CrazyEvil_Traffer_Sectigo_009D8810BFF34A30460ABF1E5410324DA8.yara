import "pe"

rule MAL_Compromised_Cert_CrazyEvil_Traffer_Sectigo_009D8810BFF34A30460ABF1E5410324DA8 {
   meta:
      description         = "Detects CrazyEvil Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-17"
      version             = "1.0"

      hash                = "d4b323c06ed57e99016411f0fb1ff66f3c20141c253ef46c4035281118c412a4"
      malware             = "CrazyEvil Traffer"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Gucheng County Sili Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:9d:88:10:bf:f3:4a:30:46:0a:bf:1e:54:10:32:4d:a8"
      cert_thumbprint     = "C739BEE07E4D6DFAA168854601BADC2232628826"
      cert_valid_from     = "2025-06-17"
      cert_valid_to       = "2026-06-17"

      country             = "CN"
      state               = "Hubei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:9d:88:10:bf:f3:4a:30:46:0a:bf:1e:54:10:32:4d:a8"
      )
}

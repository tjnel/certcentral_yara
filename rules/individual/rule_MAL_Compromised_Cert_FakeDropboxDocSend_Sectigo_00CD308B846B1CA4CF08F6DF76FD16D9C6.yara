import "pe"

rule MAL_Compromised_Cert_FakeDropboxDocSend_Sectigo_00CD308B846B1CA4CF08F6DF76FD16D9C6 {
   meta:
      description         = "Detects FakeDropboxDocSend with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-20"
      version             = "1.0"

      hash                = "430747fe54f7c3eb81ae356b87137bd610f194ce5bd546f9f68d1db7b7013750"
      malware             = "FakeDropboxDocSend"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Songyuan Wangqing Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:cd:30:8b:84:6b:1c:a4:cf:08:f6:df:76:fd:16:d9:c6"
      cert_thumbprint     = "CDCE9B7374D187C213AA7ACE50C2A6D88A9146DD"
      cert_valid_from     = "2025-08-20"
      cert_valid_to       = "2026-08-20"

      country             = "CN"
      state               = "吉林省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:cd:30:8b:84:6b:1c:a4:cf:08:f6:df:76:fd:16:d9:c6"
      )
}

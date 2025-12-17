import "pe"

rule MAL_Compromised_Cert_Amadey_stage2_Sectigo_00B34338C790556B3A8DFD62AB869A8817 {
   meta:
      description         = "Detects Amadey_stage2 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-13"
      version             = "1.0"

      hash                = "b89c2aa1d897bf0927f5b714311a70eddeb1b236fcfdd907a941372817785fee"
      malware             = "Amadey_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Huizhou Langbo Wanli Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b3:43:38:c7:90:55:6b:3a:8d:fd:62:ab:86:9a:88:17"
      cert_thumbprint     = "37D460DCDC2FAACF373CA2483F9D16D6B14FC919"
      cert_valid_from     = "2025-10-13"
      cert_valid_to       = "2026-10-13"

      country             = "CN"
      state               = "广东省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b3:43:38:c7:90:55:6b:3a:8d:fd:62:ab:86:9a:88:17"
      )
}

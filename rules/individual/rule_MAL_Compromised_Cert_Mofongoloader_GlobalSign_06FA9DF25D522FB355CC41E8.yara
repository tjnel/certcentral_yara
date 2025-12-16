import "pe"

rule MAL_Compromised_Cert_Mofongoloader_GlobalSign_06FA9DF25D522FB355CC41E8 {
   meta:
      description         = "Detects Mofongoloader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-07"
      version             = "1.0"

      hash                = "c25b566d99d55fe5cb1a19290748dac70845663fe0f8bf78f741fe4440055551"
      malware             = "Mofongoloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xuaony Plantain E-Commerce Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "06:fa:9d:f2:5d:52:2f:b3:55:cc:41:e8"
      cert_thumbprint     = "DFCDB964C7C596DBA245A066F08989C9AC1AD4B0"
      cert_valid_from     = "2024-04-07"
      cert_valid_to       = "2025-03-30"

      country             = "CN"
      state               = "Hubei"
      locality            = "Xiangyang"
      email               = "???"
      rdn_serial_number   = "91420600MACLU7R889"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "06:fa:9d:f2:5d:52:2f:b3:55:cc:41:e8"
      )
}

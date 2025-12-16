import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_5540A29447BE69FF88CF4BB5 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-24"
      version             = "1.0"

      hash                = "2b61a06ba836e0d92594b98023dcc44dc70d93adb3f9035a28cdb24903daa75a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Canton Accomplished Peak Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "55:40:a2:94:47:be:69:ff:88:cf:4b:b5"
      cert_thumbprint     = "3E0B54445FDC9916557A4885BED0A66C42E786AF"
      cert_valid_from     = "2024-05-24"
      cert_valid_to       = "2025-05-25"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440118MACC27DX2K"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "55:40:a2:94:47:be:69:ff:88:cf:4b:b5"
      )
}

import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_5014FF60D03E76D5DE85AE15 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "b89bef3b118ba3fb9261962eaee144525ee4c5a109f5817d9172cb6e67129b42"
      malware             = "Unknown"
      malware_type        = "Remote access tool"
      malware_notes       = "File masquerades as a Notepad++ installer, sets up scheduled task named Notepad Update Scheduler, which executes the nppPlugins.dll every hour. While the malware is unknown, it appears related to 1a24a12722da65ccf119dccb51aceb1eff49de9c49310d0c7af6746b43721fec which was a fake ChatGPT installer."

      signer              = "Taiyuan Jiankang Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:14:ff:60:d0:3e:76:d5:de:85:ae:15"
      cert_thumbprint     = "E0A53A952E278BDF621480F6175CC7E4FBCBD119"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-22"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "91140106MA0M4WL26F"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:14:ff:60:d0:3e:76:d5:de:85:ae:15"
      )
}

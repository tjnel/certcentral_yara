import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_418E8B8B66DADCA197FF421B {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-06"
      version             = "1.0"

      hash                = "5342fa80b4f8f983322e8932819ef6037f837b93719a77f06f48d4a6eb7b17f8"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Wuxi James Lndustrial Automation Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "41:8e:8b:8b:66:da:dc:a1:97:ff:42:1b"
      cert_thumbprint     = "EC05F66F97CCA0ECEED159E1836D571E6AB7B1E9"
      cert_valid_from     = "2025-03-06"
      cert_valid_to       = "2026-03-07"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Wuxi"
      email               = "???"
      rdn_serial_number   = "91320213MA1XXDB71G"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "41:8e:8b:8b:66:da:dc:a1:97:ff:42:1b"
      )
}

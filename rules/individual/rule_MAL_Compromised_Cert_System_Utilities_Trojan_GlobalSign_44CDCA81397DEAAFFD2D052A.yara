import "pe"

rule MAL_Compromised_Cert_System_Utilities_Trojan_GlobalSign_44CDCA81397DEAAFFD2D052A {
   meta:
      description         = "Detects System Utilities Trojan with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-07-14"
      version             = "1.0"

      hash                = "0420aa80686bd196c4c3a0d2df4cadbf25d1a2b0ba5e64c0cfede9815b645c62"
      malware             = "System Utilities Trojan"
      malware_type        = "Backdoor"
      malware_notes       = "This malware exhibits the same behaviors as anyPDF, see analysis here: https://rifteyy.org/report/system-utilities-malware-analysis"

      signer              = "Sol Digital Solutions Limited"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "44:cd:ca:81:39:7d:ea:af:fd:2d:05:2a"
      cert_thumbprint     = "B9FFBC26AB1402DEEE8A5A17DD77752FD9D8E0E1"
      cert_valid_from     = "2022-07-14"
      cert_valid_to       = "2025-07-14"

      country             = "GB"
      state               = "Greater London"
      locality            = "London"
      email               = "mail@sol-digital-solutions.com"
      rdn_serial_number   = "12577470"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "44:cd:ca:81:39:7d:ea:af:fd:2d:05:2a"
      )
}

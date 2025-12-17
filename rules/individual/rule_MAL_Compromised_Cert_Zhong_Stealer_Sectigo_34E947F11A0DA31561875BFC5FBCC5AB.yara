import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_34E947F11A0DA31561875BFC5FBCC5AB {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-08"
      version             = "1.0"

      hash                = "06663c82d1e6df0eff9712b4250e4a189a076e2592feae7753485c1dd97c6bf6"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware leverages cloud hosting to hold additional components. The components are TASLogin and its associated DLL: medium.com/@anyrun/zhong-stealer-analysis-new-malware-targeting-fintech-and-cryptocurrency-71d4a3cce42c"

      signer              = "海口市勤莱佳科技有限公司"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "34:e9:47:f1:1a:0d:a3:15:61:87:5b:fc:5f:bc:c5:ab"
      cert_thumbprint     = "9042ED33AEA56BC28C4CF03E8D03036EB8BFCF6A"
      cert_valid_from     = "2025-04-08"
      cert_valid_to       = "2026-04-08"

      country             = "CN"
      state               = "海南省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91460000MABXCETU0T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "34:e9:47:f1:1a:0d:a3:15:61:87:5b:fc:5f:bc:c5:ab"
      )
}

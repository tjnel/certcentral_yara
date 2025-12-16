import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Sectigo_009CF337C12EFC4445ECAFCB35D02D64BE {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-27"
      version             = "1.0"

      hash                = "124e8f7ca958fd8cb2a3baf91681513f93f73d9cfa4efea6f4a1f165d8cbc8d9"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Weihai Mingjun Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:9c:f3:37:c1:2e:fc:44:45:ec:af:cb:35:d0:2d:64:be"
      cert_thumbprint     = "9CBD74EBBD51F5E775142670B53B09F81C72EADD"
      cert_valid_from     = "2025-11-27"
      cert_valid_to       = "2026-11-27"

      country             = "CN"
      state               = "Shandong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91371000MA3WAC7627"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:9c:f3:37:c1:2e:fc:44:45:ec:af:cb:35:d0:2d:64:be"
      )
}

import "pe"

rule MAL_Compromised_Cert_UNK_51_Sectigo_54CC827FB58F4228CA4486B863292707 {
   meta:
      description         = "Detects UNK-51 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-21"
      version             = "1.0"

      hash                = "0896adf3b2f0cdd9d7b9dead68d558b639414f11f8342073844bba682597cfba"
      malware             = "UNK-51"
      malware_type        = "Remote access tool"
      malware_notes       = "Malware drops a DLL into the users Users Admin AppData Roaming Microsoft SystemCertificates directory. The DLL can set a scheduled task and contains an encrypted payload."

      signer              = "Huizhou Hongtai Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "54:cc:82:7f:b5:8f:42:28:ca:44:86:b8:63:29:27:07"
      cert_thumbprint     = "3592A621F023128D76677F9C96F1B33A791F393B"
      cert_valid_from     = "2025-10-21"
      cert_valid_to       = "2027-01-19"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "54:cc:82:7f:b5:8f:42:28:ca:44:86:b8:63:29:27:07"
      )
}

import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00D627F1000D12485995514BFBDEFC55D9 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-17"
      version             = "1.0"

      hash                = "27a1293d50124b0f40f4872bca6490eda7f01462dc612de6898e264bb91d9a6c"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "THREE D CORPORATION PTY LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9"
      cert_thumbprint     = "51BE49CF33BE69695216FDE854479F4E5DEE5987"
      cert_valid_from     = "2020-08-17"
      cert_valid_to       = "2021-08-17"

      country             = "AU"
      state               = "???"
      locality            = "MILL PARK"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9"
      )
}
